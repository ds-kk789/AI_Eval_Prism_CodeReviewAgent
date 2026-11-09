"""Tamper-evident audit log (hash-chained JSONL, same scheme as AuditLens auditlog.py).

Every tool call is logged with role, tool, target and decision (Task 1.4). Every entry also carries
the build, the golden-dataset hash and both dependency-lock hashes (Task 1.7); LLM entries add the
prompt-template hash and model id. Entries are secret-scrubbed unless a caller passes scrub=False,
which only the v0 reader does (planted defect DEF-002).
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from . import masking
from .settings import RUNS_DIR, build, provenance
from .util import GENESIS, canonical, chain_hash, now_utc, sha256_text, verify_chain

_lock = threading.Lock()
_last_hash: dict[str, tuple[int, str]] = {}


def run_dir(run_id: str) -> Path:
    d = RUNS_DIR / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def log_path(run_id: str) -> Path:
    return run_dir(run_id) / "audit_log.jsonl"


def read(run_id: str) -> list[dict]:
    p = log_path(run_id)
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()] if p.exists() else []


def digest(obj: Any) -> str:
    return sha256_text(canonical(obj))


def append(run_id: str, event: str, *, scrub: bool = True, **data: Any) -> dict:
    with _lock:
        if run_id not in _last_hash:
            entries = read(run_id)
            _last_hash[run_id] = (len(entries), entries[-1]["hash"] if entries else GENESIS)
        seq, prev = _last_hash[run_id]
        body = json.dumps(data, default=str, ensure_ascii=False)
        if scrub:
            body = masking.scrub(body)
        entry = {"seq": seq, "ts": now_utc().isoformat(), "run_id": run_id, "event": event, "build": build(),
                 **provenance(), **json.loads(body), "prev_hash": prev}
        entry["hash"] = chain_hash(entry)
        with log_path(run_id).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _last_hash[run_id] = (seq + 1, entry["hash"])
        return entry


def verify(run_id: str) -> dict:
    return verify_chain(read(run_id))
