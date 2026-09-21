"""CONTRACT 2 — the Finding: one confirmed problem, in a fixed format.

This schema is FROZEN (Week 2). Every detector emits these; nothing else.
Changes require agreement of all three team members (see AGENTS.md).
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


def _new_id() -> str:
    return uuid4().hex


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Evidence(BaseModel):
    url: str
    snippet: str = ""
    detail: str | None = None


class Finding(BaseModel):
    """One confirmed problem. `explanation` stays None until the explanation layer fills it."""

    finding_id: str = Field(default_factory=_new_id)
    detector_id: str
    category: str                       # see analysis/severity.py CATEGORY_MAP
    cwe_id: str | None = None           # e.g. "CWE-862"
    owasp_2025: str | None = None       # e.g. "A01:2025"
    severity: Severity = Severity.INFO
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    title: str
    evidence: list[Evidence] = Field(default_factory=list)
    remediation_hint: str = ""
    explanation: str | None = None
