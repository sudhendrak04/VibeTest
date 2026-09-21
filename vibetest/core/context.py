"""ScanContext: what the orchestrator hands to acquisition and detectors.

Lives in core/ (not detectors/) so acquisition and detectors both depend on core,
never on each other.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx

from ..config import Settings
from .consent import ConsentGate


@dataclass
class ScanContext:
    settings: Settings
    gate: ConsentGate
    # Layer-2 detectors declare needs_probes=True; the orchestrator only sets
    # allow_probes=True (and provides http) when probing is explicitly enabled.
    allow_probes: bool = False
    http: httpx.Client | None = None
