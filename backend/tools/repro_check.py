"""Artifact reproducibility check (deliverable: "artifact reproducibility check logs").

  ..\\aienv\\Scripts\\python.exe -m tools.repro_check [REFERENCE_MAIN_RUN]

Re-runs the full main evaluation from the LLM cache (0 new calls), then compares it with the
reference run: every metric that does not depend on wall-clock time must be identical, and the
golden dataset, prompt templates, model ids and dependency locks must have the same hashes.
Writes runs/repro_<ts>/repro.json.
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime

from prism import auditlog
from prism.eval import run_main
from prism.settings import RUNS_DIR, provenance

TIME_KEYS = {"latency_p95_ms", "latency_mean_ms", "p95_latency_ratio", "run_id", "tool_calls_logged", "llm",
             "audit_chain", "ledger_today", "runs", "cache_hits"}


def strip(o):
    if isinstance(o, dict):
        return {k: strip(v) for k, v in o.items() if k not in TIME_KEYS}
    if isinstance(o, list):
        return [strip(x) for x in o]
    return o


def diff(a, b, path="") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out += diff(a.get(k), b.get(k), f"{path}.{k}")
        return out
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [d for i, (x, y) in enumerate(zip(a, b)) for d in diff(x, y, f"{path}[{i}]")]
    return [] if a == b else [f"{path}: {a!r} != {b!r}"]


def main(ref: str) -> int:
    ref_res = json.loads((RUNS_DIR / ref / "results.json").read_text(encoding="utf-8"))
    new_id = asyncio.run(run_main.main(offline=False, skip_judge=False))
    new_res = json.loads((RUNS_DIR / new_id / "results.json").read_text(encoding="utf-8"))
    diffs = diff(strip(ref_res), strip(new_res))
    checks = {
        "metrics_identical": not diffs,
        "new_llm_calls": new_res["llm"]["runs"],
        "golden_sha256_same": ref_res["freeze"]["golden_sha256"] == new_res["freeze"]["golden_sha256"],
        "prompt_hashes_same": ref_res["prompt_hashes"] == new_res["prompt_hashes"],
        "models_same": ref_res["models"] == new_res["models"],
        "audit_chain_ok": new_res["audit_chain"]["ok"],
    }
    out = {"reference_run": ref, "rerun": new_id, "checked_at": datetime.now().isoformat(timespec="seconds"),
           "provenance": provenance(), "checks": checks, "differences": diffs[:50],
           "passed": all(v for k, v in checks.items() if k != "new_llm_calls") and checks["new_llm_calls"] == 0}
    d = auditlog.run_dir("repro_" + datetime.now().strftime("%Y%m%dT%H%M%S"))
    (d / "repro.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in out.items() if k != "differences"}, indent=2))
    print(f"differences: {len(diffs)} -> {d / 'repro.json'}")
    return 0 if out["passed"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "main_20261109T105643"))
