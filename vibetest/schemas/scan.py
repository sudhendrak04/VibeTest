"""ScanResult: the complete output of one scan (artifact + findings + metadata)."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .artifacts import Artifact
from .findings import Finding


class ScanResult(BaseModel):
    scan_id: str
    target_url: str
    started_at: datetime
    artifact: Artifact
    findings: list[Finding] = Field(default_factory=list)
