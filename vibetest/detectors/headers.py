"""Layer-1 detector: missing HTTP security headers (passive)."""
from __future__ import annotations

from urllib.parse import urlparse

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

# header -> (severity, cwe, owasp_2025, remediation)
SECURITY_HEADERS: dict[str, tuple[Severity, str, str, str]] = {
    "content-security-policy": (
        Severity.MEDIUM, "CWE-693", "A05:2025",
        "Add a Content-Security-Policy header to reduce XSS impact. Start with a "
        "report-only policy, then enforce.",
    ),
    "strict-transport-security": (
        Severity.MEDIUM, "CWE-319", "A02:2025",
        "Add Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains) so "
        "browsers only use HTTPS.",
    ),
    "x-content-type-options": (
        Severity.LOW, "CWE-693", "A02:2025",
        "Add X-Content-Type-Options: nosniff to stop MIME-type confusion.",
    ),
    "x-frame-options": (
        Severity.LOW, "CWE-1021", "A02:2025",
        "Add X-Frame-Options: DENY/SAMEORIGIN (or CSP frame-ancestors) to prevent "
        "clickjacking.",
    ),
    "referrer-policy": (
        Severity.LOW, "CWE-200", "A02:2025",
        "Add a Referrer-Policy header (e.g. strict-origin-when-cross-origin) to avoid "
        "leaking URLs to third parties.",
    ),
    "permissions-policy": (
        Severity.INFO, "CWE-693", "A02:2025",
        "Consider a Permissions-Policy header to disable unused browser features "
        "(camera, microphone, geolocation).",
    ),
}


@register
class SecurityHeadersDetector(BaseDetector):
    id = "headers"
    name = "Missing security headers"
    layer = 1

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        missing: dict[str, list[Evidence]] = {h: [] for h in SECURITY_HEADERS}
        for page in artifact.pages:
            present = {k.lower() for k in page.headers}
            is_https = urlparse(page.url).scheme == "https"
            for header in SECURITY_HEADERS:
                # HSTS is meaningless over plain HTTP — only flag it for HTTPS pages.
                if header == "strict-transport-security" and not is_https:
                    continue
                if header not in present:
                    missing[header].append(
                        Evidence(url=page.url, detail=f"response missing `{header}`")
                    )

        findings: list[Finding] = []
        for header, (severity, cwe, owasp, fix) in SECURITY_HEADERS.items():
            evidence = missing[header]
            if not evidence:
                continue
            findings.append(
                Finding(
                    detector_id=self.id,
                    category="missing-security-header",
                    cwe_id=cwe,
                    owasp_2025=owasp,
                    severity=severity,
                    confidence=1.0,
                    title=f"Missing security header: {header}",
                    evidence=evidence,
                    remediation_hint=fix,
                )
            )
        return findings
