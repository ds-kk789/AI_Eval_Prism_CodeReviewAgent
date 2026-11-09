"""Hashing helpers (same chain scheme as AuditLens util.py)."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

GENESIS = "0" * 64


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def chain_hash(entry: dict) -> str:
    return sha256_text(canonical({k: v for k, v in entry.items() if k != "hash"}))


def verify_chain(entries: list[dict]) -> dict:
    """Recompute the prev_hash/hash chain. Returns the first broken index, or None."""
    prev = GENESIS
    for i, entry in enumerate(entries):
        if entry.get("prev_hash") != prev or chain_hash(entry) != entry.get("hash"):
            return {"ok": False, "entries": len(entries), "broken_at": i}
        prev = entry["hash"]
    return {"ok": True, "entries": len(entries), "broken_at": None}


def now_utc() -> datetime:
    return datetime.now(timezone.utc)
