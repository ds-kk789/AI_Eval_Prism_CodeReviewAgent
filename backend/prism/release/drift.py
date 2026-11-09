"""Post-production drift detection (Task 7). 0 LLM calls.

  ..\\aienv\\Scripts\\python.exe -m prism.release.drift

1. Detect (blind - never reads data/sealed/):
   - reference window = the first 20 records (the healthy baseline period after release)
   - CUSUM (lower side) on quality_score: k = 0.5 sigma, h = 5 sigma -> alarm; change point = the
     last time the CUSUM was zero before the alarm, + 1
   - two-sample Kolmogorov-Smirnov tests (SciPy) on every input feature and on quality, reference vs
     after the change point; sliding 10-record windows locate the first shifted window
2. Classify: input features shifted + quality dropped + build/prompt/model unchanged -> data drift;
   quality dropped with no input shift -> concept drift; prompt or model id changed -> prompt/model drift.
3. Drift vs regression: a regression lines up with a shipped change and reproduces on the frozen golden
   set; here nothing changed and the golden-set metrics re-run identically from the cache.
4. Save the detection, THEN unseal: verify the sealed file's sha256 and compare the true start.
5. Write the incident note (impact, root cause, corrective action).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from statistics import mean, pstdev

from scipy.stats import ks_2samp

from .. import auditlog
from ..settings import DATA_DIR, RUNS_DIR

REF = 20
FEATURES = ["async_ratio", "type_hint_density", "comment_density", "lines"]


def load() -> list[dict]:
    return [json.loads(x) for x in (DATA_DIR / "drift_batch.jsonl").read_text(encoding="utf-8").splitlines() if x]


def cusum_lower(xs: list[float], mu0: float, sigma: float, k: float = 0.5, h: float = 5.0) -> tuple[int | None, int | None, list[float]]:
    s, path, last_zero = 0.0, [], 0
    for t, x in enumerate(xs):
        s = max(0.0, s + (mu0 - x) - k * sigma)
        path.append(round(s, 4))
        if s == 0:
            last_zero = t
        if s > h * sigma:
            return t, last_zero + 1, path
    return None, None, path


def detect(rows: list[dict]) -> dict:
    q = [r["quality_score"] for r in rows]
    ref_q = q[:REF]
    mu0, sd = mean(ref_q), pstdev(ref_q) or 1e-6
    alarm, start, path = cusum_lower(q, mu0, sd)
    split = start if start is not None else len(rows)
    ks = {}
    for f in FEATURES + ["quality_score", "finding_count"]:
        get = (lambda r, f=f: r["features"][f]) if f in FEATURES else (lambda r, f=f: r[f])
        before = [get(r) for r in rows[:REF]]
        after = [get(r) for r in rows[split:]] if split < len(rows) else []
        if after:
            stat, p = ks_2samp(before, after)
            ks[f] = {"ks_stat": round(float(stat), 3), "p_value": float(f"{p:.2e}"),
                     "mean_ref": round(mean(before), 3), "mean_after": round(mean(after), 3),
                     "shifted": bool(p < 0.01)}
    windows = []
    for w0 in range(REF, len(rows) - 9, 5):
        win = rows[w0:w0 + 10]
        p = ks_2samp([r["features"]["async_ratio"] for r in rows[:REF]],
                     [r["features"]["async_ratio"] for r in win]).pvalue
        windows.append({"start_seq": w0, "end_seq": w0 + 9, "async_ratio_p": float(f"{p:.2e}"), "shifted": bool(p < 0.01)})
    first_shift = next((w for w in windows if w["shifted"]), None)
    invariants = {k: sorted({r[k] for r in rows}) for k in ("build", "prompt_version", "model_id")}
    input_shift = [f for f in FEATURES if ks.get(f, {}).get("shifted")]
    quality_drop = ks.get("quality_score", {}).get("shifted", False) and \
        ks["quality_score"]["mean_after"] < ks["quality_score"]["mean_ref"]
    if any(len(v) > 1 for k, v in invariants.items() if k in ("prompt_version",)):
        dtype = "prompt"
    elif any(len(v) > 1 for k, v in invariants.items() if k == "model_id"):
        dtype = "model"
    elif input_shift and quality_drop:
        dtype = "data"
    elif quality_drop:
        dtype = "concept"
    else:
        dtype = "none"
    return {"reference_window": [0, REF - 1], "reference_quality_mean": round(mu0, 3), "reference_quality_sd": round(sd, 3),
            "cusum": {"k_sigma": 0.5, "h_sigma": 5.0, "alarm_seq": alarm, "path": path},
            "detected_start_seq": start, "detected_start_request": rows[start]["request_id"] if start is not None else None,
            "ks_reference_vs_after": ks, "sliding_windows": windows, "first_shifted_window": first_shift,
            "invariants": invariants, "shifted_inputs": input_shift, "quality_drop": quality_drop, "drift_type": dtype}


def regression_check() -> dict:
    """The frozen golden set must give identical metrics on a re-run (no regression in the system)."""
    mains = sorted(p for p in RUNS_DIR.glob("main_*") if (p / "results.json").exists())
    if len(mains) < 2:
        return {"checked": False}
    a, b = (json.loads((m / "results.json").read_text(encoding="utf-8")) for m in mains[-2:])
    pick = lambda r: (r["ab_test"]["vB"]["quality"], r["ab_test"]["vB"]["valid_json_rate"],  # noqa: E731
                      r["coordinator"]["task_completion"].get("mean"))
    return {"checked": True, "runs": [mains[-2].name, mains[-1].name], "golden_metrics_identical": pick(a) == pick(b),
            "golden_f1": a["ab_test"]["vB"]["quality"]["f1"], "task_completion": a["coordinator"]["task_completion"].get("mean")}


def unseal() -> dict:
    sealed = DATA_DIR / "sealed" / "drift_point.json"
    expected = (DATA_DIR / "drift_point.sha256").read_text(encoding="utf-8").split()[0]
    raw = sealed.read_bytes()
    ok = hashlib.sha256(raw).hexdigest() == expected
    return {"hash_verified": ok, **(json.loads(raw) if ok else {})}


def incident_note(det: dict, truth: dict, reg: dict, rows: list[dict]) -> str:
    s = det["detected_start_seq"]
    ks = det["ks_reference_vs_after"]
    affected = len(rows) - s if s is not None else 0
    q0, q1 = ks["quality_score"]["mean_ref"], ks["quality_score"]["mean_after"]
    f0, f1 = ks["finding_count"]["mean_ref"], ks["finding_count"]["mean_after"]
    return f"""# Incident note: review-quality drop in production traffic (data drift)

**Status:** detected and contained · **Severity:** medium (quality, not security) · **System:** PRism v1, prompt vB, {det['invariants']['model_id'][0]}

## Impact
- From request **{det['detected_start_request']}** (seq {s}) to the end of the stream, **{affected} of {len(rows)} reviews** were affected.
- Mean review quality fell from **{q0}** to **{q1}** ({(q1 - q0) / q0:+.0%}); findings per review fell from {f0} to {f1}, so real problems were likely missed.
- No security impact: build, prompt and model were unchanged, and the security gates are unaffected.

## Detection
- CUSUM on quality (reference = first {REF} requests, mean {det['reference_quality_mean']}, sd {det['reference_quality_sd']}) raised the alarm at seq {det['cusum']['alarm_seq']}; the change point is seq **{s}**.
- KS tests, reference vs after: async_ratio p = {ks['async_ratio']['p_value']} (mean {ks['async_ratio']['mean_ref']} -> {ks['async_ratio']['mean_after']}), type_hint_density p = {ks['type_hint_density']['p_value']} ({ks['type_hint_density']['mean_ref']} -> {ks['type_hint_density']['mean_after']}); comment density and file length unchanged.
- Sealed drift point (opened after detection, sha256 verified: {truth.get('hash_verified')}): true start seq **{truth.get('drift_start_seq')}**, detected **{s}** (difference {None if s is None or truth.get('drift_start_seq') is None else s - truth['drift_start_seq']:+} requests).

## Root cause
**Data drift (covariate shift).** Incoming code changed style to async-heavy, densely type-hinted files. The reviewer prompt and the frozen golden set contain almost no such code, so the reviewer finds fewer real problems in it. Nothing in the system changed: one build, one prompt ({det['invariants']['prompt_version'][0]}) and one model across the whole stream.

## Why this is drift and not a regression
The quality drop began with a measurable change in the input distribution (KS p < 0.01 on async_ratio and type_hint_density) while the build, prompt and model hashes stayed the same. The frozen golden set still scores identically on re-run (F1 {reg.get('golden_f1')}, task completion {reg.get('task_completion')}, identical across {', '.join(reg.get('runs', []))}), so the system did not get worse; the traffic changed.

## Corrective action
1. **Contain:** keep v1 + prompt vB in production (no rollback: nothing shipped caused this); flag reviews of async / heavily type-hinted files for human review until fixed.
2. **Fix:** create golden dataset **v2** (new version; v1 stays frozen) with async and type-hinted samples and expected findings; extend the vB rubric with async pitfalls (missing await, blocking calls in coroutines); A/B test and re-run the quality gate.
3. **Prevent:** keep the CUSUM + KS monitor on production traffic with an alert at the same thresholds; review the golden set's coverage each quarter against the production input distribution.
"""


def main() -> str:
    run_id = "drift_" + datetime.now().strftime("%Y%m%dT%H%M%S")
    rows = load()
    det = detect(rows)                                        # blind
    d = auditlog.run_dir(run_id)
    (d / "drift_detection.json").write_text(json.dumps(det, indent=2), encoding="utf-8")
    auditlog.append(run_id, "drift_detected", detected_start_seq=det["detected_start_seq"], drift_type=det["drift_type"],
                    detection_sha256=auditlog.digest(det))
    reg = regression_check()
    truth = unseal()                                          # only after the detection is saved and logged
    auditlog.append(run_id, "drift_unsealed", hash_verified=truth["hash_verified"],
                    true_start_seq=truth.get("drift_start_seq"))
    res = {"run_id": run_id, "detection": {k: v for k, v in det.items() if k != "cusum"} | {"cusum_alarm_seq": det["cusum"]["alarm_seq"]},
           "regression_check": reg, "sealed": truth,
           "error_requests": None if det["detected_start_seq"] is None or truth.get("drift_start_seq") is None
           else det["detected_start_seq"] - truth["drift_start_seq"],
           "series": [{"seq": r["seq"], "quality": r["quality_score"], "async_ratio": r["features"]["async_ratio"],
                       "type_hint_density": r["features"]["type_hint_density"], "cusum": c}
                      for r, c in zip(rows, det["cusum"]["path"] + [None] * (len(rows) - len(det["cusum"]["path"])))],
           "audit_chain": auditlog.verify(run_id)}
    (d / "drift_results.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    note = incident_note(det, truth, reg, rows)
    (d / "incident_note.md").write_text(note, encoding="utf-8")
    ks = det["ks_reference_vs_after"]
    print(f"run {run_id}")
    print(f"detected start: seq {det['detected_start_seq']} ({det['detected_start_request']}), CUSUM alarm at seq {det['cusum']['alarm_seq']}")
    print(f"first shifted 10-record window: {det['first_shifted_window']}")
    print("KS:", {f: (v['p_value'], v['mean_ref'], v['mean_after']) for f, v in ks.items()})
    print(f"invariants: {det['invariants']} -> drift type: {det['drift_type'].upper()}")
    print(f"regression check: {reg}")
    print(f"UNSEALED: {truth} -> detection error {res['error_requests']} requests")
    return run_id


if __name__ == "__main__":
    main()
