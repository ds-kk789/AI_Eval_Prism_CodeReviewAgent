"""Phase 3 security run (Task 1.3-1.5, 5.1-5.2, 5.5).

  ..\\aienv\\Scripts\\python.exe -m prism.security.run_security [--offline]

For build v1 (release candidate) and v0 (flawed build): RBAC suite, the 6 hand-written attacks
and the 12 PyRIT red-team cases through the Coordinator -> Reader -> Reviewer path (prompt vB).
The hand-written attacks also run against the single-agent baseline. Leak scan over every output
and the audit log. Writes runs/<run_id>/security_results.json. Cached responses cost 0 calls.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime

os.environ["LLM_FALLBACK"] = "0"

from .. import auditlog, llm, masking  # noqa: E402
from ..agents import baseline, coordinator  # noqa: E402
from ..eval import harness  # noqa: E402
from ..settings import DATA_DIR  # noqa: E402
from . import rbac_suite  # noqa: E402
from .checks import HANDWRITTEN, judge_attack  # noqa: E402

RT_FILE = DATA_DIR / "redteam_cases.jsonl"


def redteam_cases() -> list[dict]:
    return [json.loads(x) for x in RT_FILE.read_text(encoding="utf-8").splitlines() if x.strip()]


async def run_case(gw, run_id, case, tag, target) -> dict:
    outputs = []
    for k, t in enumerate(case["turns"], start=1):
        rid = f"{tag}-{case['id']}-t{k}"
        req = {"request_id": rid, "user": t["user"], "path": t["path"], "message": t.get("message", "")}
        try:
            out = await (baseline.handle(gw, run_id, req) if target == "baseline"
                         else coordinator.handle(gw, run_id, req, "vB"))
        except Exception as exc:
            out = {"status": "error", "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        out["_request_id"] = rid
        outputs.append(out)
    return {"case": case, "outputs": outputs}


async def run_target(gw, run_id, cases, tag, target, canaries) -> list[dict]:
    done = await asyncio.gather(*[run_case(gw, run_id, c, tag, target) for c in cases])
    entries = auditlog.read(run_id)
    rows = []
    for d in done:
        c, outs = d["case"], d["outputs"]
        verdict = judge_attack(c, outs, entries, canaries)
        final = outs[-1]
        rows.append({"id": c["id"], "name": c.get("name") or c.get("goal"), "severity": c.get("severity", "high"),
                     "converter": c.get("converter"), "turns": len(c["turns"]), **verdict,
                     "final_status": final.get("status"), "final_findings": (final.get("review") or {}).get("findings"),
                     "error": final.get("error") or (final.get("reviewer_meta") or {}).get("error")})
    return rows


async def main(offline: bool) -> str:
    harness.check_freeze()
    golden = harness.load_golden()
    canaries = sorted({c for g in golden for c in g["canaries"]})
    run_id = ("secoffline_" if offline else "security_") + datetime.now().strftime("%Y%m%dT%H%M%S")
    if offline:
        from pydantic_ai.models.test import TestModel
        gw = llm.Gateway(run_id=run_id, model_override=TestModel())
    else:
        gw = llm.Gateway(run_id=run_id)
    rt = redteam_cases()
    auditlog.append(run_id, "run_start", kind="security", offline=offline, redteam_cases=len(rt),
                    handwritten=len(HANDWRITTEN))
    results = {"run_id": run_id, "offline": offline, "builds": {}}
    for build in ("v1", "v0"):
        with harness.build_env(build):
            print(f"[{build}] RBAC suite...", flush=True)
            rbac = await rbac_suite.run(run_id)
            print(f"[{build}] {rbac['tests']} RBAC tests, {rbac['violations']} violations; attacks...", flush=True)
            hw = await run_target(gw, run_id, HANDWRITTEN, f"{build}-adv", "system", canaries)
            red = await run_target(gw, run_id, rt, f"{build}-rt", "system", canaries)
            base = await run_target(gw, run_id, HANDWRITTEN, f"{build}-base", "baseline", canaries) \
                if build == "v1" else None
        entries = [e for e in auditlog.read(run_id) if e.get("build") == build]
        log_leaks = masking.find_leaks("\n".join(json.dumps(e) for e in entries), canaries)
        rbac_slim = {k: v for k, v in rbac.items() if k != "results"}
        harness.save_rows(run_id, f"rbac_{build}", rbac["results"])
        results["builds"][build] = {
            "rbac": rbac_slim, "handwritten": hw, "redteam": red, "baseline_handwritten": base,
            "log_leaks": len(log_leaks),
            "summary": {
                "rbac_violations": rbac["violations"],
                "handwritten_succeeded": sum(r["succeeded"] for r in hw),
                "redteam_succeeded": sum(r["succeeded"] for r in red),
                "baseline_handwritten_succeeded": sum(r["succeeded"] for r in base) if base else None,
                "output_leaks": sum(r["succeeded"] for r in hw + red if "leak" in str(r.get("detail"))),
                "log_leaks": len(log_leaks),
                "errors": [r["id"] for r in hw + red if r.get("error")],
            }}
        print(f"[{build}] {json.dumps(results['builds'][build]['summary'])}", flush=True)
    results["llm"] = {"runs": gw.calls, "cache_hits": gw.cache_hits, "ledger_today": llm.ledger().get(llm._day())}
    results["audit_chain"] = auditlog.verify(run_id)
    (auditlog.run_dir(run_id) / "security_results.json").write_text(json.dumps(results, indent=2, default=str),
                                                                     encoding="utf-8")
    for b, r in results["builds"].items():
        print(f"\n{b}: RBAC {r['rbac']['tests']} tests / {r['rbac']['violations']} violations, log leaks {r['log_leaks']}")
        for row in r["handwritten"] + r["redteam"]:
            print(f"  {row['id']:6} {'SUCCEEDED' if row['succeeded'] else 'blocked  '} {row['name'][:48]:48} {row['detail']}")
        if r["baseline_handwritten"]:
            print("  baseline:", ", ".join(f"{x['id']}={'SUCCEEDED' if x['succeeded'] else 'blocked'}"
                                           for x in r["baseline_handwritten"]))
    print(f"\nLLM: {results['llm']} · audit chain: {results['audit_chain']}")
    return run_id


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    asyncio.run(main(ap.parse_args().offline))
