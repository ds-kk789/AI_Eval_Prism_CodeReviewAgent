"""Phase 1 live smoke test: 2 golden samples x (reviewer vA, reviewer vB, baseline), build v1.
Run from backend/:  ..\\aienv\\Scripts\\python.exe -m tools.smoke
"""
from __future__ import annotations

import asyncio
import json
import os

os.environ["LLM_FALLBACK"] = "0"
os.environ.setdefault("PRISM_BUILD", "v1")

from prism import auditlog, llm, masking  # noqa: E402
from prism.agents import baseline, coordinator  # noqa: E402
from prism.settings import GOLDEN_FILE  # noqa: E402

IDS = ["G006", "G012"]


async def main() -> None:
    golden = {r["id"]: r for r in map(json.loads, GOLDEN_FILE.read_text(encoding="utf-8").splitlines())}
    run_id = "smoke_v1"
    gw = llm.Gateway(run_id=run_id)
    all_canaries = sorted({c for r in golden.values() for c in r["canaries"]})
    for gid in IDS:
        g = golden[gid]
        expected = sorted((f["line"], f["severity"]) for f in g["expected_findings"])
        req = {"request_id": f"{gid}", "user": g["user"], "path": g["file"]}
        jobs = {"vA": coordinator.handle(gw, run_id, {**req, "request_id": f"{gid}-vA"}, "vA"),
                "vB": coordinator.handle(gw, run_id, {**req, "request_id": f"{gid}-vB"}, "vB"),
                "baseline": baseline.handle(gw, run_id, {**req, "request_id": f"{gid}-base"})}
        results = dict(zip(jobs, await asyncio.gather(*jobs.values(), return_exceptions=True)))
        print(f"\n{gid} {g['file']}  expected {expected}")
        for name, out in results.items():
            if isinstance(out, Exception):
                print(f"  {name:8} ERROR {type(out).__name__}: {str(out)[:200]}")
                continue
            got = sorted((f["line"], f["severity"]) for f in out["review"]["findings"])
            t = out["trace"]
            m = out.get("reviewer_meta", {})
            print(f"  {name:8} json={out['valid_json']} findings={got} tokens={t['tokens']} "
                  f"llm_req={t['llm_calls']} latency={t['latency_ms']}ms cache={m.get('cache_hit')} "
                  f"guard={out.get('guard')} {('ERR ' + m['error']) if m.get('error') else ''}")
    log = auditlog.log_path(run_id).read_text(encoding="utf-8")
    print(f"\naudit chain: {auditlog.verify(run_id)} | canary leaks in log: {masking.find_leaks(log, all_canaries)}")
    print(f"LLM calls this run: {gw.calls}, cache hits: {gw.cache_hits}, ledger today: {llm.ledger().get(llm._day())}")


if __name__ == "__main__":
    asyncio.run(main())
