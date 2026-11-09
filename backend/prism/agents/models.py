"""Typed data passed between agents (output spec, Task 3.1)."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class Finding(BaseModel):
    file: str
    line: int = Field(ge=1)
    severity: Severity
    comment: str = Field(min_length=5, max_length=400)


class Review(BaseModel):
    file: str
    findings: list[Finding] = Field(default_factory=list, max_length=20)


class Handoff(BaseModel):
    """v1 Coordinator -> Reviewer envelope. The task is fixed and the code is a separate field that
    is never parsed for instructions, so file content cannot rewrite the handoff (DEF-005 control)."""
    request_id: str
    file: str
    role: Literal["reviewer", "admin"]
    task: Literal["review"] = "review"
    code: str
    line_count: int
