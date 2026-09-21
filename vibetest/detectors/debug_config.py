"""Layer-2 detector: development/debug build markers shipped to production.

High-confidence markers only (precision-first): development builds in production
expose verbose error messages, internal component/file names, and debug code
paths to every visitor.
"""
from __future__ import annotations

import re

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

_MAX_EVIDENCE = 3

_MARKERS: tuple[tuple[re.Pattern, Severity, float, str, str], ...] = (
    (
        re.compile(r"react-dom\.development"),
        Severity.MEDIUM,
        0.95,
        "React development build shipped to production",
        "Build and deploy a production bundle (NODE_ENV=production). Development builds "
        "include verbose error messages, internal component names, and debug tooling.",
    ),
    (
        re.compile(r"""NODE_ENV["']?\s*[:=]\s*["']development["']"""),
        Severity.MEDIUM,
        0.85,
        "Development environment marker in shipped code (NODE_ENV=development)",
        "Deploy with NODE_ENV=production so development code paths and debug helpers are "
        "stripped from the shipped files.",
    ),
)


def _context(content: str, match: re.Match) -> str:
    start = max(0, match.start() - 50)
    end = min(len(content), match.end() + 50)
    return content[start:end].replace("\n", " ").strip()


@register
class DebugConfigDetector(BaseDetector):
    id = "debug_config"
    name = "Development/debug build markers"
    layer = 2
    # No probes needed: works purely on already-collected pages and bundles.

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        haystacks = [(p.url, p.html) for p in artifact.pages] + [
            (b.url, b.content) for b in artifact.js_bundles
        ]
        findings: list[Finding] = []
        for regex, severity, confidence, title, remediation in _MARKERS:
            evidence: list[Evidence] = []
            for url, content in haystacks:
                match = regex.search(content)
                if match is None:
                    continue
                evidence.append(Evidence(url=url, snippet=_context(content, match)))
                if len(evidence) >= _MAX_EVIDENCE:
                    break
            if evidence:
                findings.append(
                    Finding(
                        detector_id=self.id,
                        category="debug-config",
                        cwe_id="CWE-489",
                        owasp_2025="A02:2025",
                        severity=severity,
                        confidence=confidence,
                        title=title,
                        evidence=evidence,
                        remediation_hint=remediation,
                    )
                )
        return findings
