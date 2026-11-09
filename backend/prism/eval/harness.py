"""Async evaluation harness (Task 1.1). Runs every golden sample concurrently through the
multi-agent system, the single-agent baseline or the v0 build; throughput is limited only by the
gateway's per-provider rate limiter and concurrency settings.

Before any run the golden set is checked against its frozen sha256 (MANIFEST.json). The first live
run writes data/golden/v1.first_run; after that the generator refuses to rewrite the dataset.
"""
from __future__ import annotations

import asyncio
import json
import os
from contextlib import contextmanager
from pathlib import Path

from .. import auditlog
from ..agents import baseline, coordinator, reader
from ..llm import Gateway
from ..settings import DATA_DIR, GOLDEN_FILE, sha256_file
from ..util import now_utc

MANIFEST = DATA_DIR / "golden" / "MANIFEST.json"
FIRST_RUN = DATA_DIR / "golden" / "v1.first_run"


def load_golden() -> list[dict]:
    return [json.loads(x) for x in GOLDEN_FILE.read_text(encoding="utf-8").splitlines() if x.strip()]


def check_freeze() -> dict:
    """The golden file and every sample must still match the frozen manifest."""
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    problems = []
    if sha256_file(GOLDEN_FILE) != manifest["golden_sha256"]:
        problems.append("golden v1.jsonl changed")
    for rel, sha in manifest["samples"].items():
        if sha256_file(DATA_DIR / rel) != sha:
            problems.append(f"{rel} changed")
    if problems:
        raise RuntimeError("golden dataset is not the frozen version: " + "; ".join(problems))
    return {"golden_sha256": manifest["golden_sha256"], "samples": len(manifest["samples"]),
            "read_only": not os.access(GOLDEN_FILE, os.W_OK)}


def mark_first_run(run_id: str) -> None:
    if not FIRST_RUN.exists():
        FIRST_RUN.write_text(json.dumps({"run_id": run_id, "at": now_utc().isoformat()}), encoding="utf-8")


@contextmanager
def build_env(build: str):
    old = os.environ.get("PRISM_BUILD")
    os.environ["PRISM_BUILD"] = build
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("PRISM_BUILD", None)
        else:
            os.environ["PRISM_BUILD"] = old


def _request(g: dict, tag: str) -> dict:
    return {"request_id": f"{tag}-{g['id']}", "user": g["user"], "path": g["file"]}


async def _one(fn, g: dict, mode: str, **kw) -> dict:
    try:
        out = await fn(**kw)
    except Exception as exc:                                            # keep the run going; record the error
        out = {"status": "error", "error": f"{type(exc).__name__}: {str(exc)[:300]}", "review": None,
               "valid_json": False, "trace": {"steps": 0, "llm_calls": 0, "tokens": 0, "latency_ms": 0}}
    return {"id": g["id"], "file": g["file"], "category": g["category"], "mode": mode, **out}


async def run_system(gw: Gateway, run_id: str, golden: list[dict], prompt_version: str, tag: str) -> list[dict]:
    return list(await asyncio.gather(*[
        _one(coordinator.handle, g, f"system_{prompt_version}", gw=gw, run_id=run_id,
             req=_request(g, tag), prompt_version=prompt_version) for g in golden]))


async def run_baseline(gw: Gateway, run_id: str, golden: list[dict], tag: str = "base") -> list[dict]:
    return list(await asyncio.gather(*[
        _one(baseline.handle, g, "baseline", gw=gw, run_id=run_id, req=_request(g, tag)) for g in golden]))


async def run_reader_probes(run_id: str, golden: list[dict]) -> list[dict]:
    """Deterministic RBAC probes on the Reader (0 LLM calls): every restricted file requested as a
    reviewer (plain and with a ../ traversal variant) must be denied; as admin it must be allowed."""
    probes = []
    for g in golden:
        if not g["restricted"]:
            continue
        name = Path(g["file"]).name
        probes += [(g, "reviewer", g["file"], "deny"), (g, "admin", g["file"], "allow"),
                   (g, "reviewer", f"./samples/secrets/../secrets/{name}", "deny")]
    probes.append((None, "reviewer", "../config/policy.csv", "deny"))
    out = []
    for n, (g, role, path, expected) in enumerate(probes):
        r = await reader.read(run_id, f"probe-{n:02d}", path, role)
        out.append({"probe": n, "golden_id": g["id"] if g else None, "role": role, "path": path,
                    "expected": expected, "decision": r["decision"], "content": r["content"]})
    return out


def save_rows(run_id: str, name: str, rows: list[dict]) -> Path:
    p = auditlog.run_dir(run_id) / f"{name}.jsonl"
    p.write_text("".join(json.dumps(r, ensure_ascii=False, default=str) + "\n" for r in rows), encoding="utf-8")
    return p


def load_rows(run_id: str, name: str) -> list[dict]:
    p = auditlog.run_dir(run_id) / f"{name}.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []
