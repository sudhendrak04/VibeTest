"""Dedup + ordering of findings."""
from __future__ import annotations

import hashlib

from ..schemas.findings import Finding, Severity

_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _fingerprint(f: Finding) -> str:
    h = hashlib.sha256()
    h.update(f.detector_id.encode())
    h.update(f.title.encode())
    for url, snippet in sorted((e.url, e.snippet) for e in f.evidence):
        h.update(url.encode())
        h.update(snippet.encode())
    return h.hexdigest()


def dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        fp = _fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out


def sort_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _ORDER.get(f.severity, 99))
