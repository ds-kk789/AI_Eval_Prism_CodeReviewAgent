"""Golden dataset data-quality validators (Task 2.3).

The two validators the brief asks for:
  1. no_duplicates           - no repeated id, file or sample content (sha256), no repeated finding
  2. required_fields_present - every record and every expected finding has all required, non-empty fields

Supporting checks (reported, and they also fail the dataset):
  - composition     - 20-30 samples, at least 5 clean and 5 adversarial (Task 2.2)
  - findings_valid  - severity in the allowed set, 1 <= line <= line_count, finding file == record file
  - samples_match   - each sample file on disk still has the sha256 recorded in the golden set
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd
import pandera.pandas as pa

REQUIRED = ["id", "version", "file", "category", "user", "role", "restricted", "expected_decision",
            "line_count", "sha256", "expected_findings", "canaries"]
FINDING_REQUIRED = ["file", "line", "severity", "comment"]
SEVERITIES = {"low", "medium", "high", "critical"}
CATEGORIES = {"clean", "buggy", "adversarial", "secret"}


def load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _schema() -> pa.DataFrameSchema:
    nonempty = pa.Check(lambda s: s.astype(str).str.len() > 0, element_wise=False, error="empty value")
    return pa.DataFrameSchema(
        {
            "id": pa.Column(str, [nonempty], unique=True, nullable=False),
            "version": pa.Column(str, [nonempty], nullable=False),
            "file": pa.Column(str, [nonempty], unique=True, nullable=False),
            "category": pa.Column(str, pa.Check.isin(sorted(CATEGORIES)), nullable=False),
            "user": pa.Column(str, [nonempty], nullable=False),
            "role": pa.Column(str, pa.Check.isin(["reviewer", "admin"]), nullable=False),
            "restricted": pa.Column(bool, nullable=False),
            "expected_decision": pa.Column(str, pa.Check.isin(["allow", "deny"]), nullable=False),
            "line_count": pa.Column(int, pa.Check.gt(0), nullable=False),
            "sha256": pa.Column(str, pa.Check.str_length(64, 64), unique=True, nullable=False),
            "expected_findings": pa.Column(object, nullable=False),
            "canaries": pa.Column(object, nullable=False),
        },
        strict=False,
    )


def _run(name: str, fn) -> dict:
    try:
        problems = fn()
    except pa.errors.SchemaErrors as e:
        problems = [f"{r['column']}: {r['check']} (row {r['index']})"
                    for r in e.failure_cases[["column", "check", "index"]].to_dict("records")]
    except pa.errors.SchemaError as e:
        problems = [str(e).splitlines()[0]]
    return {"name": name, "passed": not problems, "problems": problems}


def validate_golden(path: str | Path, samples_root: str | Path | None = None) -> dict:
    path = Path(path)
    root = Path(samples_root) if samples_root else path.parent.parent      # backend/data
    records = load(path)
    df = pd.DataFrame(records)

    def required_fields():
        problems = [f"missing column '{c}'" for c in REQUIRED if c not in df.columns]
        for r in records:
            for c in REQUIRED:
                if r.get(c) is None or (isinstance(r.get(c), str) and not r[c].strip()):
                    problems.append(f"{r.get('id', '?')}: missing or empty '{c}'")
            for k, f in enumerate(r.get("expected_findings") or []):
                for c in FINDING_REQUIRED:
                    if f.get(c) in (None, ""):
                        problems.append(f"{r['id']} finding {k}: missing '{c}'")
        if not problems:
            _schema().validate(df[REQUIRED], lazy=True)
        return problems

    def no_duplicates():
        problems = []
        for col in ("id", "file", "sha256"):
            dup = df[col][df[col].duplicated()].tolist()
            problems += [f"duplicate {col}: {v}" for v in dup]
        for r in records:
            keys = [(f["line"], f["comment"].strip().lower()) for f in r["expected_findings"]]
            if len(keys) != len(set(keys)):
                problems.append(f"{r['id']}: duplicate expected finding")
        return problems

    def composition():
        n = len(records)
        cats = df["category"].value_counts().to_dict()
        problems = []
        if not 20 <= n <= 30:
            problems.append(f"{n} samples; the brief requires 20 to 30")
        if cats.get("clean", 0) < 5:
            problems.append(f"{cats.get('clean', 0)} clean samples; need at least 5")
        if cats.get("adversarial", 0) < 5:
            problems.append(f"{cats.get('adversarial', 0)} adversarial samples; need at least 5")
        return problems

    def findings_valid():
        problems = []
        for r in records:
            if r["category"] == "clean" and r["expected_findings"]:
                problems.append(f"{r['id']}: clean sample has expected findings")
            if r["category"] != "clean" and not r["expected_findings"]:
                problems.append(f"{r['id']}: non-clean sample has no expected findings")
            for f in r["expected_findings"]:
                if f["severity"] not in SEVERITIES:
                    problems.append(f"{r['id']}: bad severity {f['severity']}")
                if not 1 <= f["line"] <= r["line_count"]:
                    problems.append(f"{r['id']}: line {f['line']} outside 1..{r['line_count']}")
                if f["file"] != r["file"]:
                    problems.append(f"{r['id']}: finding file {f['file']} != {r['file']}")
        return problems

    def samples_match():
        problems = []
        for r in records:
            p = root / r["file"]
            if not p.exists():
                problems.append(f"{r['id']}: {r['file']} missing")
                continue
            data = p.read_bytes()
            if hashlib.sha256(data).hexdigest() != r["sha256"]:
                problems.append(f"{r['id']}: {r['file']} sha256 changed")
            if len(data.decode("utf-8").splitlines()) != r["line_count"]:
                problems.append(f"{r['id']}: line_count mismatch")
        return problems

    checks = [_run("required_fields_present", required_fields), _run("no_duplicates", no_duplicates),
              _run("composition", composition), _run("findings_valid", findings_valid),
              _run("samples_match", samples_match)]
    return {
        "dataset": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "records": len(records),
        "passed": all(c["passed"] for c in checks),
        "checks": checks,
    }


if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[2] / "data/golden/v1.jsonl"
    print(json.dumps(validate_golden(target), indent=2))
