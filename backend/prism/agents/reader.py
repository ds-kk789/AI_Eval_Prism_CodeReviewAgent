"""Reader agent: deterministic (0 LLM calls). Fetches code through the MCP read_file tool, which
enforces role-based access and masks secrets and PII."""
from __future__ import annotations

import time

from ..mcp_tools.server import call


async def read(run_id: str, request_id: str, path: str, role: str) -> dict:
    t0 = time.perf_counter()
    res = await call("read_file", path=path, role=role, run_id=run_id, request_id=request_id, agent="reader")
    res["latency_ms"] = int((time.perf_counter() - t0) * 1000)
    return res
