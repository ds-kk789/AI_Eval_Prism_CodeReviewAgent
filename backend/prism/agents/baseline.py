"""Single-agent baseline: one LLM agent does every step itself. It decides when to call the two MCP
tools (read_source_file, lint_code), reviews, and returns JSON. The tools are bound to the
caller's role, so the LLM can never choose its own role. No separate Reader, no handoff and no
output guard: only the schema check, so the comparison isolates the multi-agent design.
"""
from __future__ import annotations

import json
import time
from functools import lru_cache
from string import Template

import jsonschema
from pydantic_ai import Agent

from .. import auditlog
from ..llm import Gateway
from ..mcp_tools.server import bound_toolset
from ..settings import PROMPTS_DIR, SCHEMAS_DIR, build, users
from ..util import sha256_text
from .models import Review


@lru_cache
def _template() -> tuple[Template, str]:
    text = (PROMPTS_DIR / "baseline.md").read_text(encoding="utf-8")
    return Template(text), sha256_text(text)[:12]


async def handle(gw: Gateway, run_id: str, req: dict) -> dict:
    t0 = time.perf_counter()
    rid, path = req["request_id"], req["path"]
    role = users().get(req["user"])
    if role is None:
        return {"status": "denied", "reason": "unknown user", "trace": {"steps": 1, "llm_calls": 0}}
    auditlog.append(run_id, "route", agent="baseline", request_id=rid, user=req["user"], role=role, target=path,
                    decision="start")
    tpl, phash = _template()
    prompt = tpl.safe_substitute(file=path, message=req.get("message", ""))
    agent = Agent(output_type=Review, name="baseline", retries=1)
    meta: dict = {"prompt_version": "baseline", "prompt_hash": phash}
    try:
        raw, m = await gw.run_agent(agent_name="baseline", agent=agent, prompt=prompt, prompt_hash=phash,
                                    request_id=rid, toolsets=[bound_toolset(role, run_id, rid)],
                                    cache_extra=f"{build()}|{role}", max_requests=6, expected_requests=3)
        meta.update(m)
        jsonschema.validate(raw, json.loads((SCHEMAS_DIR / "review.schema.json").read_text(encoding="utf-8")))
        valid = True
    except Exception as exc:
        raw, valid = {"file": path, "findings": []}, False
        meta["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    usage = meta.get("usage") or {}
    tool_calls = meta.get("tool_calls", [])
    return {"status": "ok", "role": role, "review": raw, "valid_json": valid, "reviewer_meta": meta,
            "trace": {"steps": 1 + len(tool_calls), "llm_calls": usage.get("requests", 0) or 0,
                      "tokens": usage.get("total_tokens", 0) or 0, "tool_calls": tool_calls,
                      "latency_ms": int((time.perf_counter() - t0) * 1000), "llm_latency_ms": meta.get("latency_ms", 0)}}
