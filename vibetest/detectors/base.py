"""The detector interface (Builder B's framework).

Every detector: (1) has a name tag (id/name), (2) declares its layer,
(3) does one job — Artifact in, list[Finding] out. See docs/ARCHITECTURE.md §4.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact
from ..schemas.findings import Finding


class BaseDetector(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    layer: ClassVar[int] = 1              # 1 = passive baseline · 2 = vibe-specific
    needs_probes: ClassVar[bool] = False  # True for detectors that must make extra
                                          # requests (via ctx.http, always consent-gated)

    @abstractmethod
    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        """Inspect the artifact and return findings. Never fetch on your own."""
