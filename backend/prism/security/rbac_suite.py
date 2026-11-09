"""RBAC test suite (Task 1.3 / 5.2). Deterministic, 0 LLM calls.

Every user x every sample file x several path spellings is sent to the Reader. Expected decision:
admin may read every sample; reviewers are denied anything that normalises to samples/secrets/*;
anything outside samples/ (config, .env, absolute paths) is denied for everyone; unknown users are
denied by the Coordinator."""
from __future__ import annotations

from pathlib import Path

from ..agents import reader
from ..settings import DATA_DIR, users
from .checks import is_restricted


def _variants(rel: str) -> list[str]:
    name = Path(rel).name
    folder = str(Path(rel).parent).replace("\\", "/")
    out = [rel, f"./{rel}", rel.replace("/", "\\")]
    if folder.endswith("secrets"):
        out += [f"samples/secrets/../secrets/{name}", f"samples//secrets/{name}", f"samples/./secrets/{name}",
                f"samples/redteam/../secrets/{name}"]
    return out


def cases() -> list[dict]:
    files = sorted(str(p.relative_to(DATA_DIR)).replace("\\", "/") for p in (DATA_DIR / "samples").rglob("*.py"))
    out = []
    for user, role in sorted(users().items()):
        for f in files:
            for path in _variants(f):
                exp = "allow" if role == "admin" or not is_restricted(path) else "deny"
                out.append({"user": user, "role": role, "path": path, "expected": exp})
        for path in ["../config/policy.csv", "samples/../../.env", "C:/Windows/win.ini", "/etc/passwd",
                     "samples/../config/roles.yaml"]:
            out.append({"user": user, "role": role, "path": path, "expected": "deny"})
    return out


async def run(run_id: str) -> dict:
    results = []
    for n, c in enumerate(cases()):
        r = await reader.read(run_id, f"rbac-{n:04d}", c["path"], c["role"])
        results.append({**c, "decision": r["decision"], "reason": r["reason"]})
    viol = [r for r in results if r["decision"] != r["expected"]]
    by_role = {}
    for r in results:
        s = by_role.setdefault(r["role"], {"tests": 0, "violations": 0})
        s["tests"] += 1
        s["violations"] += r["decision"] != r["expected"]
    return {"tests": len(results), "violations": len(viol), "by_role": by_role,
            "violation_examples": viol[:10], "results": results}
