# PRism — evaluate, secure and release an AI code review agent system

*by Kenneth Yeo · Capstone Problem Statement 3*

PRism builds a three-agent code review system (Coordinator → Reader → Reviewer over two MCP tools,
plus a single-agent baseline), then proves how well it works, finds where it fails, puts controls
around it and decides whether it is safe to release.

**Start here:** open [`reports/index.html`](reports/index.html), the release decision, with links to
every deliverable. Design: [`doc/PRism_System_Design.html`](doc/PRism_System_Design.html).

## Result

**GO (conditional) for build v1 with reviewer prompt vB.** The quality gate passes 9/9 (exit 0):
- valid JSON 100%, correct tool calls 100%, task completion 0.915
- 0 hallucinated comments, 0 leaks, 0 RBAC violations in 339 tests
- 0 of 18 attacks succeeded (including 12 PyRIT red-team cases)
- the 3-agent system uses 0.35× the tokens of a single agent at 1.12× the finding F1

The flawed build v0 fails the gate (exit 1). All 6 planted defects are documented with evidence in
[`backend/defects/`](backend/defects/). The canary rolled back on an SLA breach, then promoted to
100%. Blind drift detection found data drift at request 51; the sealed truth is 50.

Two conditions apply to the release:
1. Send reviews of async or heavily type-hinted code to a human until golden v2 is built.
2. Fix QUAL-001, the gap in privacy-finding recall.

## Setup (Windows, Python 3.11+; built on 3.13)

```bash
python -m venv aienv
python -m venv aienv-redteam
cd backend
../aienv/Scripts/python.exe -m pip install -r requirements.txt
../aienv-redteam/Scripts/python.exe -m pip install -r requirements-redteam.txt
cp .env.example .env      # then fill in GOOGLE_API_KEY, GROQ_API_KEY, GROQ_API_KEY_2; set LLM_FALLBACK=0
```

There are two virtual environments because PyRIT 1.1 and DeepEval 4.3 need incompatible `click`
versions; `pip check` found the clash. `aienv-redteam` only generates the red-team cases.
Exact versions are pinned in `requirements.lock` and `requirements-redteam.lock`.

## Run (from `backend/`)

| Step | Command | LLM calls |
|---|---|---|
| Offline tests (no keys) | `../aienv/Scripts/python.exe -m pytest -q` | 0 |
| Starter kit + frozen golden set (already done, refuses to rerun) | `../aienv/Scripts/python.exe -m tools.make_kit` | 0 |
| Red-team cases (PyRIT converters) | `../aienv-redteam/Scripts/python.exe -m tools.make_redteam` | 0 |
| Main evaluation: A/B, per-agent, baseline, DeepEval | `../aienv/Scripts/python.exe -m prism.eval.run_main` | ~112 Gemini + ~20 Groq first time, 0 cached |
| Security: RBAC, attacks, red team (v1 and v0) | `../aienv/Scripts/python.exe -m prism.security.run_security` | ~35 first time |
| Quality gate (exit 0 PASS / 1 FAIL) | `../aienv/Scripts/python.exe -m prism.gate --build v1` | 0 |
| Canary with SLA and rollback | `../aienv/Scripts/python.exe -m prism.release.canary` | 0 (cache) |
| Drift detection + incident note | `../aienv/Scripts/python.exe -m prism.release.drift` | 0 |
| Reproducibility check | `../aienv/Scripts/python.exe -m tools.repro_check` | 0 (cache) |
| HTML reports → `reports/` | `../aienv/Scripts/python.exe -m prism.report.render` | 0 |

Add `--offline` to `run_main` or `run_security` to run the whole pipeline with a fake model.
Every LLM response is cached by prompt hash in `backend/runs/.llm_cache/`, so any re-run is free.
A daily ledger enforces the call caps in `config/budgets.yaml`.

## Layout

```
backend/prism/        agents/ mcp_tools/ eval/ security/ release/ report/ llm.py masking.py auditlog.py gate.py
backend/config/       roles, Casbin policy, restricted files, budgets, thresholds, compliance checklist
backend/data/         samples/ (20 golden + 12 red-team carriers), golden/v1 (frozen), replay, drift stream, sealed/
backend/defects/      DEF-001..006 (system) and EVAL-001..004 (evaluation harness), with evidence
backend/runs/         run folders, audit logs, LLM cache (git-ignored)
reports/              the 10 HTML deliverable pages + evidence/ copies of the run files
doc/                  brief, system design, report mockup
```

## Security notes

- API keys are kept only in `backend/.env`, which is git-ignored. The quality gate scans tracked files for key patterns.
- All secrets and emails in the samples are fake canaries. Masking happens inside the read tool, before any LLM call or log write.
- `reports/` was scanned for every canary and key pattern before commit: 26 files, 0 hits.
