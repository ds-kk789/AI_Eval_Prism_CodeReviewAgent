"""Reviewer agent: calls the MCP lint tool, then one LLM call, and returns a JSON review.

v1: typed output (pydantic) + jsonschema check + output guard:
    - findings on lines outside 1..line_count are dropped (anti-hallucination)
    - lint floor: security/correctness lint issues the LLM left out are added back, so an
      injected "ignore all issues" cannot suppress them (DEF-004 control)
v0: planted weaknesses - free-text handoff whose embedded '"task": "..."' is obeyed (DEF-005),
    naive prompt that says to follow notes in the code (DEF-004), and no schema enforcement or
    line check (DEF-006).
"""
from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from string import Template

import jsonschema
from pydantic_ai import Agent

from ..llm import Gateway
from ..mcp_tools.server import call
from ..settings import PROMPTS_DIR, SCHEMAS_DIR
from ..util import sha256_text
from .models import Handoff, Review

# Lint rules treated as real findings by the lint floor, with their severity.
LINT_SEVERITY = {"S": "high", "F821": "high", "E722": "medium", "B006": "medium", "F401": "low", "E711": "low"}


@lru_cache
def template(version: str) -> tuple[Template, str]:
    text = (PROMPTS_DIR / f"reviewer_{version}.md").read_text(encoding="utf-8")
    return Template(text), sha256_text(text)[:12]


@lru_cache
def schema() -> dict:
    return json.loads((SCHEMAS_DIR / "review.schema.json").read_text(encoding="utf-8"))


def _lint_text(issues: list[dict]) -> str:
    return "; ".join(f"line {i['line']} {i['rule']}: {i['message']}" for i in issues) or "none"


def _lint_severity(rule: str) -> str | None:
    return LINT_SEVERITY.get(rule) or (LINT_SEVERITY["S"] if rule.startswith("S") else None)


def guard(review: dict, file: str, line_count: int, lint_issues: list[dict]) -> tuple[dict, dict]:
    """v1 output guard. Returns (clean review, counters)."""
    kept, dropped = [], 0
    for f in review.get("findings", []):
        if 1 <= int(f.get("line", 0)) <= line_count:
            kept.append({**f, "file": file})
        else:
            dropped += 1
    lines = {f["line"] for f in kept}
    added = 0
    for i in lint_issues:
        sev = _lint_severity(i["rule"])
        if sev and i["line"] not in lines and 1 <= i["line"] <= line_count:
            kept.append({"file": file, "line": i["line"], "severity": sev,
                         "comment": f"[lint {i['rule']}] {i['message']}"})
            lines.add(i["line"])
            added += 1
    return {"file": file, "findings": kept}, {"dropped_out_of_range": dropped, "added_from_lint": added}


def _parse_loose(text: str) -> dict | None:
    m = re.search(r"\{.*\}", text or "", re.S)
    try:
        return json.loads(m.group(0)) if m else None
    except json.JSONDecodeError:
        return None


async def review_v1(gw: Gateway, run_id: str, h: Handoff, prompt_version: str) -> dict:
    t0 = time.perf_counter()
    lint = await call("lint", code=h.code, file=h.file, role=h.role, run_id=run_id,
                      request_id=h.request_id, agent="reviewer")
    tpl, phash = template(prompt_version)
    numbered = "\n".join(f"{n:>3} | {line}" for n, line in enumerate(h.code.splitlines(), start=1))
    prompt = tpl.safe_substitute(file=h.file, line_count=h.line_count, code=h.code, numbered_code=numbered,
                                 lint=_lint_text(lint["issues"]))
    agent = Agent(output_type=Review, name=f"reviewer_{prompt_version}", retries=1)
    meta: dict = {"prompt_version": prompt_version, "prompt_hash": phash}
    try:
        raw, m = await gw.run_agent(agent_name=f"reviewer_{prompt_version}", agent=agent, prompt=prompt,
                                    prompt_hash=phash, request_id=h.request_id, cache_extra="v1")
        meta.update(m)
        jsonschema.validate(raw, schema())
        valid_json = True
    except (jsonschema.ValidationError, Exception) as exc:   # model returned unusable output
        raw, valid_json = {"file": h.file, "findings": []}, False
        meta["error"] = f"{type(exc).__name__}: {str(exc)[:200]}"
    clean, counters = guard(raw, h.file, h.line_count, lint["issues"])
    return {"review": clean, "raw": raw, "valid_json": valid_json, "lint": lint["issues"], "guard": counters,
            "meta": meta, "latency_ms": int((time.perf_counter() - t0) * 1000)}


async def review_v0(gw: Gateway, run_id: str, handoff_text: str, file: str, role: str, request_id: str) -> dict:
    t0 = time.perf_counter()
    code = handoff_text.split("code:\n", 1)[-1]
    lint = await call("lint", code=code, file=file, role=role, run_id=run_id, request_id=request_id, agent="reviewer")
    task = re.search(r'"task"\s*:\s*"(\w+)"', handoff_text)          # DEF-005: obeys a task found anywhere
    if task and task.group(1) != "review":
        return {"review": {"file": file, "findings": []}, "raw": None, "valid_json": True, "lint": lint["issues"],
                "guard": {}, "meta": {"prompt_version": "v0", "hijacked_task": task.group(1)},
                "latency_ms": int((time.perf_counter() - t0) * 1000)}
    tpl, phash = template("v0")
    prompt = tpl.safe_substitute(handoff=handoff_text, lint=_lint_text(lint["issues"]))
    agent = Agent(output_type=str, name="reviewer_v0")
    meta: dict = {"prompt_version": "v0", "prompt_hash": phash}
    try:
        text, m = await gw.run_agent(agent_name="reviewer_v0", agent=agent, prompt=prompt, prompt_hash=phash,
                                     request_id=request_id, cache_extra="v0")
        meta.update(m)
    except Exception as exc:
        text, meta["error"] = "", f"{type(exc).__name__}: {str(exc)[:200]}"
    raw = _parse_loose(text)
    valid = raw is not None
    if valid:
        try:
            jsonschema.validate(raw, schema())
        except jsonschema.ValidationError:
            valid = False
    review = raw if isinstance(raw, dict) else {"file": file, "findings": []}
    review.setdefault("findings", [])
    return {"review": review, "raw": text, "valid_json": valid, "lint": lint["issues"], "guard": {},
            "meta": meta, "latency_ms": int((time.perf_counter() - t0) * 1000)}
