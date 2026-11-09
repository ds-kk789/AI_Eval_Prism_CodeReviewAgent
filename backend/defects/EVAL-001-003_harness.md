# Evaluation-harness defects found in phase 2 (9 Nov 2026)

These are defects in how PRism *measured* the system, not in the system under test. Each was found in
a recorded run, kept on disk as evidence, then fixed. The golden dataset was not changed.

| ID | Defect | Evidence | Impact | Fix | Verified in |
|---|---|---|---|---|---|
| EVAL-001 | p95 latency included time each request spent queued behind the harness's own rate limiter (all 60 requests start together) | `runs/main_20261109T101447/results.md`: system p95 423,587 ms, baseline 240,189 ms | Latency and the efficiency gate measured the test harness, not the system | Gateway records `queue_ms`; `metrics.effective_latency` = end-to-end minus queue time (cache hit: plus the stored LLM latency) | `runs/main_20261109T103502`: system p95 4,336 ms, baseline 24,940 ms |
| EVAL-002 | DeepEval judge never saw the code under review and had format words in its task; Groq structured output failed to parse in 4 of 20 cases | `runs/main_20261109T101447/task_completion.jsonl`: clean-file reviews scored 0.0-0.2 ("returned an empty list"); 4 `ModelRequestRejectedError ... Parsing failed` | Task completion 0.24, not a valid measurement | Masked, line-numbered code in the test case; task judged on substance; prompted JSON output; 400 "Parsing failed" retried | `runs/main_20261109T103502` (still low, see EVAL-003) |
| EVAL-003 | DeepEval `TaskCompletionMetric` summarises the outcome from tool calls and drops the review content, so correct reviews still scored 0.0-0.2 | `runs/main_20261109T103502/task_completion.jsonl` (G001 0.15, G005 0.0 for correct empty reviews) and `runs/main_20261109T103502_judgeprobe` | Metric unsuitable for a single-shot review output | Replaced with DeepEval G-Eval "Task Completion": reference-based steps against the golden expected findings, 1 judge call per sample | judge probe: clean G002 1.0, buggy G006 1.0, adversarial G012/G016 1.0; full run `main_*` after this fix |
| EVAL-004 | Baseline tool correctness read the audit log, which has no baseline tool calls on a cache hit (the LLM is not re-run) | `runs/main_20261109T105108/results.md`: baseline 0% (live run `main_20261109T101447`: 90%) | Cached re-runs were not reproducible for this metric | Score the baseline from the tool calls recorded with its answer (stored in the cache) | cached re-run after this fix |

Budget note: the two judge runs used 101 Groq requests (~81K tokens) across accounts 1 and 2. The
self-imposed cap was raised from 55 to 120 requests per key (real limits: 1K requests, 200K tokens/day).
