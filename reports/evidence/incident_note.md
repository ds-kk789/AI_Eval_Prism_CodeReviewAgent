# Incident note: review-quality drop in production traffic (data drift)

**Status:** detected and contained · **Severity:** medium (quality, not security) · **System:** PRism v1, prompt vB, gemini-3.5-flash-lite

## Impact
- From request **P051** (seq 51) to the end of the stream, **29 of 80 reviews** were affected.
- Mean review quality fell from **0.853** to **0.643** (-25%); findings per review fell from 1.6 to 0.862, so real problems were likely missed.
- No security impact: build, prompt and model were unchanged, and the security gates are unaffected.

## Detection
- CUSUM on quality (reference = first 20 requests, mean 0.853, sd 0.055) raised the alarm at seq 54; the change point is seq **51**.
- KS tests, reference vs after: async_ratio p = 7.07e-14 (mean 0.049 -> 0.572), type_hint_density p = 7.07e-14 (0.197 -> 0.667); comment density and file length unchanged.
- Sealed drift point (opened after detection, sha256 verified: True): true start seq **50**, detected **51** (difference +1 requests).

## Root cause
**Data drift (covariate shift).** Incoming code changed style to async-heavy, densely type-hinted files. The reviewer prompt and the frozen golden set contain almost no such code, so the reviewer finds fewer real problems in it. Nothing in the system changed: one build, one prompt (reviewer_vB) and one model across the whole stream.

## Why this is drift and not a regression
The quality drop began with a measurable change in the input distribution (KS p < 0.01 on async_ratio and type_hint_density) while the build, prompt and model hashes stayed the same. The frozen golden set still scores identically on re-run (F1 0.8947, task completion 0.915, identical across main_20261109T105108, main_20261109T105643), so the system did not get worse; the traffic changed.

## Corrective action
1. **Contain:** keep v1 + prompt vB in production (no rollback: nothing shipped caused this); flag reviews of async / heavily type-hinted files for human review until fixed.
2. **Fix:** create golden dataset **v2** (new version; v1 stays frozen) with async and type-hinted samples and expected findings; extend the vB rubric with async pitfalls (missing await, blocking calls in coroutines); A/B test and re-run the quality gate.
3. **Prevent:** keep the CUSUM + KS monitor on production traffic with an alert at the same thresholds; review the golden set's coverage each quarter against the production input distribution.
