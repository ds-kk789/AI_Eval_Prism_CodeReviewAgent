"""Canary rollout simulation with SLA check and automatic rollback (Task 6).

  ..\\aienv\\Scripts\\python.exe -m prism.release.canary

Stable = build v1 with reviewer prompt vA (current production). Candidate = build v1 with prompt vB
(the A/B winner). The 60-request replay (data/traffic_replay.jsonl) is served in three stages of 20
requests: 10%, 50%, 100% of traffic to the candidate. Routing is deterministic: a request goes to
the candidate when sha256(request_id) mod 100 < stage percent.

SLA (one SLA, config/thresholds.yaml): the candidate's p95 service latency over the requests it served
in a stage must be <= 8,000 ms. Hard stop: any planted secret in a candidate response. A breach rolls
traffic back to 0% candidate immediately and the rollout stops.

Attempt 1 replays the file as given: requests 3-8 carry an injected 9,000 ms latency fault on the
candidate (degraded infrastructure). Attempt 2 replays it after the fault is resolved. Responses
come from the LLM cache (0 calls); service latency = local processing + the LLM latency originally
measured for that response (+ the injected fault).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime

os.environ["LLM_FALLBACK"] = "0"

from .. import auditlog, llm, masking  # noqa: E402
from ..agents import coordinator  # noqa: E402
from ..eval import harness  # noqa: E402
from ..eval.metrics import effective_latency, p95  # noqa: E402
from ..settings import DATA_DIR, thresholds  # noqa: E402

STABLE, CANDIDATE = "vA", "vB"


def load_replay() -> list[dict]:
    return [json.loads(x) for x in (DATA_DIR / "traffic_replay.jsonl").read_text(encoding="utf-8").splitlines() if x]


def route(request_id: str, pct: float) -> str:
    return CANDIDATE if int(hashlib.sha256(request_id.encode()).hexdigest(), 16) % 100 < pct * 100 else STABLE


async def attempt(gw, run_id: str, name: str, replay: list[dict], with_fault: bool, canaries: list[str]) -> dict:
    cfg = thresholds()["canary"]
    stages, window, sla = cfg["stages"], cfg["window"], cfg["sla_p95_latency_ms"]
    log, served = [], {"stable": 0, "candidate": 0}
    pct, stage_i, status = stages[0], 0, "in_progress"

    def event(kind, **kw):
        e = {"attempt": name, "event": kind, "candidate_pct": pct, **kw}
        log.append(e)
        auditlog.append(run_id, "canary", **{("canary_event" if k == "event" else k): v for k, v in e.items()})

    event("stage_start", stage=1)
    stage_lat: list[float] = []
    for n, r in enumerate(replay):
        arm = route(r["request_id"], pct) if pct > 0 else STABLE
        req = {"request_id": f"{name}-{r['request_id']}", "user": r["user"], "path": r["file"]}
        out = await coordinator.handle(gw, run_id, req, arm)
        lat = effective_latency(out) if out.get("status") == "ok" else (out.get("trace") or {}).get("latency_ms", 0)
        fault = r["candidate_fault_latency_ms"] if (with_fault and arm == CANDIDATE) else 0
        lat += fault
        leak = bool(masking.find_leaks(json.dumps(out, default=str), canaries))
        served["candidate" if arm == CANDIDATE else "stable"] += 1
        event("request", seq=r["seq"], request_id=r["request_id"], arm=arm, status=out.get("status"),
              latency_ms=round(lat), injected_fault_ms=fault, leak=leak)
        if arm == CANDIDATE:
            stage_lat.append(lat)
            if leak:
                event("sla_breach", reason="planted secret in a candidate response (hard stop)", seq=r["seq"])
                pct, status = 0.0, "rolled_back"
                event("rollback", to="stable", reason="hard stop")
        if status == "in_progress" and (n + 1) % window == 0:          # end of a stage
            cand_p95 = p95(stage_lat) if stage_lat else None
            ok = cand_p95 is not None and cand_p95 <= sla
            event("sla_check", stage=stage_i + 1, candidate_requests=len(stage_lat), candidate_p95_ms=cand_p95,
                  sla_ms=sla, passed=ok)
            if not ok:
                event("sla_breach", reason=f"candidate p95 {cand_p95} ms > SLA {sla} ms" if cand_p95 is not None
                      else "no candidate traffic to verify", stage=stage_i + 1)
                pct, status = 0.0, "rolled_back"
                event("rollback", to="stable", reason="SLA breach", remaining_requests=len(replay) - n - 1)
            elif stage_i + 1 < len(stages):
                stage_i += 1
                pct = stages[stage_i]
                stage_lat = []
                event("promote", stage=stage_i + 1)
            else:
                status = "promoted"
                event("rollout_complete", stage=stage_i + 1)
    return {"attempt": name, "with_fault": with_fault, "status": status, "final_candidate_pct": pct,
            "served": served, "events": log}


async def main() -> str:
    harness.check_freeze()
    canaries = sorted({c for g in harness.load_golden() for c in g["canaries"]})
    run_id = "canary_" + datetime.now().strftime("%Y%m%dT%H%M%S")
    gw = llm.Gateway(run_id=run_id)
    replay = load_replay()
    cfg = thresholds()["canary"]
    auditlog.append(run_id, "run_start", kind="canary", stable=STABLE, candidate=CANDIDATE, sla=cfg)
    with harness.build_env("v1"):
        a1 = await attempt(gw, run_id, "attempt1", replay, True, canaries)
        a2 = await attempt(gw, run_id, "attempt2", replay, False, canaries)
    res = {"run_id": run_id, "stable": f"v1 + prompt {STABLE}", "candidate": f"v1 + prompt {CANDIDATE}",
           "sla": f"candidate p95 service latency <= {cfg['sla_p95_latency_ms']} ms per {cfg['window']}-request stage; "
                  "hard stop on any planted secret in a candidate response",
           "attempts": [{k: v for k, v in a.items() if k != "events"} for a in (a1, a2)],
           "llm": {"new_calls": gw.calls, "cache_hits": gw.cache_hits}, "audit_chain": auditlog.verify(run_id)}
    d = auditlog.run_dir(run_id)
    (d / "canary_log.jsonl").write_text("".join(json.dumps(e) + "\n" for e in a1["events"] + a2["events"]),
                                        encoding="utf-8")
    (d / "canary_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    for a in (a1, a2):
        print(f"\n{a['attempt']} (fault={'on' if a['with_fault'] else 'resolved'}): {a['status'].upper()}, "
              f"served {a['served']}")
        for e in a["events"]:
            if e["event"] != "request" or e.get("injected_fault_ms"):
                print("  ", {k: v for k, v in e.items() if k != "attempt"})
    print(f"\nLLM new calls: {gw.calls}, cache hits: {gw.cache_hits}; audit chain {res['audit_chain']}")
    return run_id


if __name__ == "__main__":
    asyncio.run(main())
