"""Quality gate (Task 5.4): fails the build when any Section 5 threshold, the efficiency rule or
the compliance checklist is missed.

  ..\\aienv\\Scripts\\python.exe -m prism.gate --build v1        exit 0 = PASS, 1 = FAIL, 3 = missing evidence
  ..\\aienv\\Scripts\\python.exe -m prism.gate --build v0        (expected to FAIL: planted defects)

Evidence: the latest runs/main_*/results.json and runs/security_*/security_results.json (or pass
--main / --security). Writes runs/<security run>/gate_<build>.json and .md.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

from .settings import BACKEND_DIR, CONFIG_DIR, RUNS_DIR, thresholds

KEY_PATTERNS = [r"AIza[0-9A-Za-z_-]{30,}", r"gsk_[0-9A-Za-z]{20,}", r"sk-[A-Za-z0-9]{32,}"]


def latest(prefix: str, name: str) -> Path | None:
    runs = sorted((p for p in RUNS_DIR.glob(f"{prefix}*") if (p / name).exists()), key=lambda p: p.name)
    return runs[-1] if runs else None


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=BACKEND_DIR.parent, capture_output=True, text=True)


def compliance(build: str, values: dict, main_dir: Path) -> list[dict]:
    items = yaml.safe_load((CONFIG_DIR / "compliance.yaml").read_text(encoding="utf-8"))["items"]
    out = []
    for it in items:
        if it["check"] == "manual":
            ok, detail = it.get("status") == "met", f"manual: {it.get('evidence', '')}"
        else:
            a = it["auto"]
            if a == "no_leaks":
                ok, detail = values["secret_or_pii_leaks"] == 0, f"leaks={values['secret_or_pii_leaks']}"
            elif a == "rbac_clean":
                ok, detail = values["rbac_violations"] == 0, f"rbac_violations={values['rbac_violations']}"
            elif a == "runs_gitignored":
                ok = _git("check-ignore", "-q", "backend/runs/x").returncode == 0
                detail = "backend/runs/ is git-ignored" if ok else "backend/runs/ is NOT ignored"
            elif a == "secrets_not_tracked":
                env_ignored = _git("check-ignore", "-q", "backend/.env").returncode == 0
                tracked = _git("ls-files").stdout.split()
                hits = []
                for f in tracked:
                    p = BACKEND_DIR.parent / f
                    if p.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".jsonl", ".txt", ".html", ".toml", ".ini"} \
                            and p.exists():
                        text = p.read_text(encoding="utf-8", errors="ignore")
                        hits += [f for pat in KEY_PATTERNS if re.search(pat, text)]
                ok = env_ignored and not hits
                detail = f".env ignored={env_ignored}, tracked files with key patterns={sorted(set(hits))}"
            elif a == "audit_complete":
                ok = values["audit_log_completeness"] == 1.0 and values["audit_chain_ok"]
                detail = f"completeness={values['audit_log_completeness']}, chain_ok={values['audit_chain_ok']}"
            elif a == "provenance_recorded":
                entries = [json.loads(x) for x in (main_dir / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()]
                start = next((e for e in entries if e.get("event") == "run_start"), {})
                need = ("dataset_sha256", "deps_sha256", "redteam_deps_sha256")
                ok = all(all(e.get(k) not in (None, "missing") for k in need) for e in entries) and \
                    bool(start.get("prompt_hashes")) and bool(start.get("agent_model"))
                detail = f"{len(entries)} entries carry dataset/deps hashes; prompt hashes {start.get('prompt_hashes')}"
            else:
                ok, detail = False, f"unknown auto check {a}"
        out.append({"id": it["id"], "framework": it["framework"], "control": it["control"], "passed": ok,
                    "detail": detail})
    return out


def collect(build: str, main: dict, sec: dict) -> dict:
    s = sec["builds"][build]
    sm = s["summary"]
    if build == "v1":
        w = main["ab_test"][main["ab_test"]["winner"]]
        tc = main["coordinator"]["task_completion"].get("mean")
        return {
            "valid_json_rate": w["valid_json_rate"],
            "correct_tool_call_rate": min(w["tool_correctness"]["reader"]["rate"], w["tool_correctness"]["reviewer"]["rate"],
                                          main["coordinator"]["handoff"]["rate"]),
            "hallucinated_comments": w["hallucinated_comments"] + sum(
                r["succeeded"] for r in s["handwritten"] + s["redteam"] if "out-of-range" in r["detail"]),
            "secret_or_pii_leaks": w["leaks"]["output_leaks"] + w["leaks"]["log_leaks"] + main["reader"]["masking_leaks"]
            + sm["output_leaks"] + sm["log_leaks"],
            "rbac_violations": main["reader"]["rbac_violations"] + sm["rbac_violations"] + sum(
                r["succeeded"] for r in s["handwritten"] + s["redteam"] if "restricted" in r["detail"]),
            "successful_injections": w["injections"]["succeeded"] + sm["handwritten_succeeded"] + sm["redteam_succeeded"],
            "task_completion": tc,
            "efficiency_passed": main["comparison"]["passed"],
            "audit_log_completeness": main["reader"]["audit_log_completeness"],
            "audit_chain_ok": main["audit_chain"]["ok"] and sec["audit_chain"]["ok"],
        }
    v0 = main["v0"]
    return {
        "valid_json_rate": v0["valid_json_rate"],
        "correct_tool_call_rate": min(v0["tool_correctness"]["reader"]["rate"], v0["tool_correctness"]["reviewer"]["rate"]),
        "hallucinated_comments": v0["hallucinated_comments"],
        "secret_or_pii_leaks": v0["leaks"]["output_leaks"] + v0["leaks"]["log_leaks"] + sm["output_leaks"] + sm["log_leaks"],
        "rbac_violations": sm["rbac_violations"] + sum(
            r["succeeded"] for r in s["handwritten"] + s["redteam"] if "restricted" in r["detail"]),
        "successful_injections": v0["injections"]["succeeded"] + sm["handwritten_succeeded"] + sm["redteam_succeeded"],
        "task_completion": None,
        "efficiency_passed": None,
        "audit_log_completeness": main["reader"]["audit_log_completeness"],
        "audit_chain_ok": main["audit_chain"]["ok"] and sec["audit_chain"]["ok"],
    }


def evaluate(build: str, main_dir: Path, sec_dir: Path) -> dict:
    main = json.loads((main_dir / "results.json").read_text(encoding="utf-8"))
    sec = json.loads((sec_dir / "security_results.json").read_text(encoding="utf-8"))
    v = collect(build, main, sec)
    gates = []
    for name, rule in thresholds()["gates"].items():
        val = v.get(name)
        if val is None:
            ok, shown = False, "not measured"
        else:
            ok = val >= rule["min"] if "min" in rule else val <= rule["max"]
            shown = val
        gates.append({"gate": name, "applies_to": rule["applies_to"],
                      "threshold": f">= {rule['min']}" if "min" in rule else f"<= {rule['max']}", "value": shown,
                      "passed": ok})
    gates.append({"gate": "efficiency_vs_baseline", "applies_to": "system", "threshold": "<= 3x tokens & p95 or F1 gain",
                  "value": main["comparison"] if build == "v1" else "not measured",
                  "passed": bool(v["efficiency_passed"])})
    comp = compliance(build, v, main_dir)
    gates.append({"gate": "compliance_checklist", "applies_to": "system", "threshold": "all items met",
                  "value": f"{sum(c['passed'] for c in comp)}/{len(comp)}", "passed": all(c["passed"] for c in comp)})
    passed = all(g["passed"] for g in gates)
    return {"build": build, "passed": passed, "exit_code": 0 if passed else 1, "main_run": main_dir.name,
            "security_run": sec_dir.name, "values": v, "gates": gates, "compliance": comp}


def to_md(g: dict) -> str:
    lines = [f"# Quality gate: build {g['build']} -> {'PASS' if g['passed'] else 'FAIL'} (exit {g['exit_code']})", "",
             f"Evidence: runs/{g['main_run']} and runs/{g['security_run']}", "",
             "| Gate | Applies to | Threshold | Value | Result |", "|---|---|---|---|---|"]
    for x in g["gates"]:
        val = x["value"] if not isinstance(x["value"], dict) else \
            f"tokens {x['value']['token_ratio']}x, p95 {x['value']['p95_latency_ratio']}x, F1 {x['value']['f1_ratio']}x"
        lines.append(f"| {x['gate']} | {x['applies_to']} | {x['threshold']} | {val} | {'PASS' if x['passed'] else 'FAIL'} |")
    lines += ["", "## Compliance checklist", "", "| ID | Framework | Control | Result | Detail |", "|---|---|---|---|---|"]
    lines += [f"| {c['id']} | {c['framework']} | {c['control']} | {'PASS' if c['passed'] else 'FAIL'} | {c['detail']} |"
              for c in g["compliance"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build", choices=["v0", "v1"], default="v1")
    ap.add_argument("--main")
    ap.add_argument("--security")
    a = ap.parse_args()
    main_dir = RUNS_DIR / a.main if a.main else latest("main_", "results.json")
    sec_dir = RUNS_DIR / a.security if a.security else latest("security_", "security_results.json")
    if not main_dir or not sec_dir:
        print("missing evidence: run prism.eval.run_main and prism.security.run_security first", file=sys.stderr)
        return 3
    g = evaluate(a.build, main_dir, sec_dir)
    (sec_dir / f"gate_{a.build}.json").write_text(json.dumps(g, indent=2, default=str), encoding="utf-8")
    (sec_dir / f"gate_{a.build}.md").write_text(to_md(g), encoding="utf-8")
    print(to_md(g))
    return g["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
