"""LLM gateway (ported from AuditLens llm.py). Every LLM call in PRism goes through here.

- role "agent": Gemini Flash-Lite (Reviewer, baseline). role "judge": Groq gpt-oss-120b (DeepEval).
  Models come from config/budgets.yaml; keys from backend/.env and are never logged.
- Responses are cached by a hash of (agent, prompt-template hash, model, input): a re-run costs 0 calls.
- A daily ledger (runs/.llm_ledger.json, Pacific-time day = provider reset) enforces the call caps.
- Every call is written to the audit log with prompt hash, model id and token usage.
- LLM_FALLBACK=1 adds Groq behind Gemini (demos only; evaluation uses 0).
"""
from __future__ import annotations

import asyncio
import json
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from . import auditlog
from .settings import RUNS_DIR, budgets, env
from .util import sha256_text

CACHE_DIR = RUNS_DIR / ".llm_cache"
LEDGER = RUNS_DIR / ".llm_ledger.json"
_ledger_lock = threading.Lock()


class BudgetExceeded(RuntimeError):
    pass


class RateLimiter:
    """At most `rpm` request starts in any 60-second window (FIFO)."""

    def __init__(self, rpm: int):
        from collections import deque
        self.rpm, self.times, self.lock = rpm, deque(), None

    async def acquire(self, n: int = 1) -> None:
        import time
        if self.lock is None:
            self.lock = asyncio.Lock()
        n = min(n, self.rpm)
        async with self.lock:
            while True:
                now = time.monotonic()
                while self.times and now - self.times[0] > 60:
                    self.times.popleft()
                if len(self.times) + n <= self.rpm:
                    self.times.extend([now] * n)
                    return
                await asyncio.sleep(60 - (now - self.times[0]) + 0.2)


_LIMITERS: dict[str, RateLimiter] = {}


def limiter(family: str) -> RateLimiter:
    if family not in _LIMITERS:
        _LIMITERS[family] = RateLimiter(int(budgets().get("rpm", {}).get(family.split(":")[0], 10)))
    return _LIMITERS[family]


def _day() -> str:
    return datetime.now(ZoneInfo("America/Los_Angeles")).strftime("%Y-%m-%d")


def ledger() -> dict:
    return json.loads(LEDGER.read_text(encoding="utf-8")) if LEDGER.exists() else {}


def _charge(family: str, n: int = 1) -> int:
    """family is a ledger key: "gemini", "groq" or "groq:GROQ_API_KEY_2" (each key = its own quota)."""
    cap = int(budgets()["daily_call_caps"][family.split(":")[0]])
    with _ledger_lock:
        data = ledger()
        today = data.setdefault(_day(), {})
        if today.get(family, 0) + n > cap:
            raise BudgetExceeded(f"daily {family} cap of {cap} calls reached (resets midnight Pacific)")
        today[family] = today.get(family, 0) + n
        LEDGER.parent.mkdir(parents=True, exist_ok=True)
        LEDGER.write_text(json.dumps(data, indent=1), encoding="utf-8")
        return today[family]


@dataclass
class Target:
    family: str
    model: str
    key_env: str


def target(role: str) -> Target:
    m = budgets()["models"]["judge" if role == "judge" else "agent"]
    key_env = m.get("key", "GOOGLE_API_KEY" if m["provider"] == "gemini" else "GROQ_API_KEY")
    return Target(m["provider"], m["model"], key_env)


def build_model(role: str):
    from pydantic_ai.models.google import GoogleModel
    from pydantic_ai.models.groq import GroqModel
    from pydantic_ai.providers.google import GoogleProvider
    from pydantic_ai.providers.groq import GroqProvider

    t = target(role)
    key = env(t.key_env) or (env("GROQ_API_KEY_2") if t.family == "groq" else None)
    if not key:
        return None
    if t.family == "gemini":
        primary = GoogleModel(t.model, provider=GoogleProvider(api_key=key))
    else:
        primary = GroqModel(t.model, provider=GroqProvider(api_key=key))
    if env("LLM_FALLBACK", "0") == "1" and t.family == "gemini" and env("GROQ_API_KEY"):
        from pydantic_ai.models.fallback import FallbackModel
        backup = GroqModel(budgets()["models"]["judge"]["model"], provider=GroqProvider(api_key=env("GROQ_API_KEY")))
        return FallbackModel(primary, backup)
    return primary


@dataclass
class Gateway:
    run_id: str
    model_override: Any = None          # tests inject a FunctionModel here (no keys, no calls)
    judge_override: Any = None
    calls: int = 0
    cache_hits: int = 0
    _sems: dict = field(default_factory=dict)

    def model(self, role: str):
        if role == "judge" and self.judge_override is not None:
            return self.judge_override
        if self.model_override is not None:
            return self.model_override
        return build_model(role)

    def _overridden(self, role: str) -> bool:
        return self.model_override is not None or (role == "judge" and self.judge_override is not None)

    def model_id(self, role: str) -> str:
        if self._overridden(role):
            m = self.judge_override if role == "judge" and self.judge_override is not None else self.model_override
            return f"override:{getattr(m, 'model_name', 'function')}"
        t = target(role)
        return f"{t.family}/{t.model}"

    def _sem(self, family: str) -> asyncio.Semaphore:
        if family not in self._sems:
            self._sems[family] = asyncio.Semaphore(int(budgets()["concurrency"].get(family.split(":")[0], 1)))
        return self._sems[family]

    async def run_agent(self, *, agent_name: str, agent, prompt: str, prompt_hash: str, request_id: str,
                        role: str = "agent", deps=None, toolsets=None, max_requests: int = 6,
                        cache_extra: str = "", expected_requests: int = 1) -> tuple[Any, dict]:
        """Run a pydantic-ai agent with cache, ledger, retry and audit. Returns (output, meta)."""
        from pydantic_ai.usage import UsageLimits

        model_id = self.model_id(role)
        key = sha256_text(f"{agent_name}|{prompt_hash}|{model_id}|{cache_extra}|{prompt}")
        cached = CACHE_DIR / f"{key}.json"
        if cached.exists():
            hit = json.loads(cached.read_text(encoding="utf-8"))
            self.cache_hits += 1
            auditlog.append(self.run_id, "llm_call", agent=agent_name, request_id=request_id, cache_hit=True,
                            model=model_id, prompt_hash=prompt_hash, usage=hit["usage"])
            return hit["output"], {**hit["meta"], "cache_hit": True}

        model = self.model(role)
        if model is None:
            raise RuntimeError(f"no API key for role {role!r}: set it in backend/.env")
        if self._overridden(role):
            family = "override"
        else:
            t = target(role)
            family = t.family if t.key_env in ("GOOGLE_API_KEY", "GROQ_API_KEY") else f"{t.family}:{t.key_env}"
        q0 = asyncio.get_running_loop().time()
        async with self._sem(family):
            if family != "override":
                await limiter(family).acquire(expected_requests)
            t0 = asyncio.get_running_loop().time()
            queue_ms = int((t0 - q0) * 1000)
            result = await self._run_with_retry(agent, prompt, model, family, deps, toolsets,
                                                UsageLimits(request_limit=max_requests))
        latency_ms = int((asyncio.get_running_loop().time() - t0) * 1000)
        u = result.usage
        if family != "override" and (u.requests or 1) > 1:
            with _ledger_lock:                        # tool-using runs make several billed requests
                data = ledger()
                data.setdefault(_day(), {})[family] = data.get(_day(), {}).get(family, 0) + u.requests - 1
                LEDGER.write_text(json.dumps(data, indent=1), encoding="utf-8")
        usage = {"requests": u.requests, "input_tokens": u.input_tokens, "output_tokens": u.output_tokens,
                 "total_tokens": (u.input_tokens or 0) + (u.output_tokens or 0)}
        out = result.output
        dumped = out.model_dump() if hasattr(out, "model_dump") else out
        messages = json.loads(result.all_messages_json()) if hasattr(result, "all_messages_json") else []
        tool_calls = [{"tool": p.get("tool_name"), "args": p.get("args")} for m in messages
                      for p in m.get("parts", []) if p.get("part_kind") == "tool-call"]
        meta = {"model": model_id, "usage": usage, "latency_ms": latency_ms, "tool_calls": tool_calls}
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached.write_text(json.dumps({"output": dumped, "usage": usage, "meta": meta}, ensure_ascii=False),
                          encoding="utf-8")
        auditlog.append(self.run_id, "llm_call", agent=agent_name, request_id=request_id, cache_hit=False,
                        model=model_id, prompt_hash=prompt_hash, usage=usage, latency_ms=latency_ms,
                        output_sha256=auditlog.digest(dumped))
        return dumped, {**meta, "cache_hit": False, "queue_ms": queue_ms}

    async def _run_with_retry(self, agent, prompt, model, family, deps, toolsets, limits, attempts: int = 3):
        for attempt in range(attempts):
            if family != "override":
                _charge(family)
            self.calls += 1
            try:
                kw = {"deps": deps, "model": model, "usage_limits": limits}
                if toolsets:
                    kw["toolsets"] = toolsets
                return await agent.run(prompt, **kw)
            except Exception as exc:
                text = str(exc) + "".join(str(e) for e in getattr(exc, "exceptions", []))
                transient = any(t in text for t in ("503", "UNAVAILABLE", "429", "rate limit", "Rate limit",
                                                    "RESOURCE_EXHAUSTED", "Parsing failed", "failed_generation"))
                if not transient or attempt == attempts - 1:
                    raise
                await asyncio.sleep(10 * (attempt + 1))
