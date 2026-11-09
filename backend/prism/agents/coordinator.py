"""Coordinator agent: deterministic routing (0 LLM calls). Sends each request to the Reader,
hands the result to the Reviewer, and returns the final review with a trace (agent-to-agent).

v1: the role comes only from the authenticated user (config/roles.yaml); the handoff is a typed
    envelope (models.Handoff).
v0: planted weaknesses - a role written in the request message ("role: admin") overrides the
    caller's role (DEF-003), and the handoff is free text with the code pasted in (DEF-005).
"""
from __future__ import annotations

import re
import time

from .. import auditlog
from ..llm import Gateway
from ..settings import build, users
from . import reader, reviewer
from .models import Handoff

_ROLE_IN_TEXT = re.compile(r"(?i)\b(?:role\s*[:=]\s*|as\s+(?:an?\s+)?)(admin)\b")


async def handle(gw: Gateway, run_id: str, req: dict, prompt_version: str = "vA") -> dict:
    """req: {request_id, user, path, message?}. Returns {status, review?, trace}."""
    t0 = time.perf_counter()
    rid, path, msg = req["request_id"], req["path"], req.get("message", "")
    steps: list[dict] = []
    role = users().get(req["user"])
    if role is None:
        auditlog.append(run_id, "route", agent="coordinator", request_id=rid, user=req["user"], decision="deny",
                        reason="unknown user")
        return {"status": "denied", "reason": "unknown user", "trace": {"steps": 1, "llm_calls": 0}}
    if build() == "v0" and (m := _ROLE_IN_TEXT.search(msg)):
        role = m.group(1).lower()                                     # DEF-003
    auditlog.append(run_id, "route", agent="coordinator", request_id=rid, user=req["user"], role=role,
                    target=path, decision="route_to_reader")
    steps.append({"agent": "coordinator", "action": "route"})

    r = await reader.read(run_id, rid, path, role)
    steps.append({"agent": "reader", "action": "read_file", "decision": r["decision"], "latency_ms": r["latency_ms"]})
    if r["decision"] != "allow":
        return {"status": "denied", "reason": r["reason"], "role": role,
                "trace": _trace(steps, t0, None)}

    if build() == "v0":
        handoff_text = f"task: review\nfile: {r['path']}\nrole: {role}\ncode:\n{r['content']}"
        auditlog.append(run_id, "handoff", agent="coordinator", to="reviewer", request_id=rid, target=r["path"],
                        format="free_text")
        steps.append({"agent": "coordinator", "action": "handoff"})
        out = await reviewer.review_v0(gw, run_id, handoff_text, r["path"], role, rid)
    else:
        h = Handoff(request_id=rid, file=r["path"], role=role, code=r["content"], line_count=r["line_count"])
        auditlog.append(run_id, "handoff", agent="coordinator", to="reviewer", request_id=rid, target=h.file,
                        task=h.task, role=role, code_sha256=auditlog.digest(h.code), format="typed")
        steps.append({"agent": "coordinator", "action": "handoff"})
        out = await reviewer.review_v1(gw, run_id, h, prompt_version)
    steps.append({"agent": "reviewer", "action": "lint+llm", "latency_ms": out["latency_ms"],
                  "cache_hit": out["meta"].get("cache_hit")})
    return {"status": "ok", "role": role, "review": out["review"], "valid_json": out["valid_json"],
            "lint": out["lint"], "guard": out["guard"], "reviewer_meta": out["meta"], "raw": out["raw"],
            "trace": _trace(steps, t0, out["meta"])}


def _trace(steps: list[dict], t0: float, meta: dict | None) -> dict:
    usage = (meta or {}).get("usage") or {}
    return {"steps": len(steps), "path": steps, "llm_calls": usage.get("requests", 0) or 0,
            "tokens": usage.get("total_tokens", 0) or 0, "latency_ms": int((time.perf_counter() - t0) * 1000),
            "llm_latency_ms": (meta or {}).get("latency_ms", 0)}
