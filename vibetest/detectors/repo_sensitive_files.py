"""Layer-1 detector (repo mode): sensitive files committed to the repository.

Runs only on repository artifacts (relative file paths). A `.env`, a Firebase
service-account key, an SSH key or a credentials file sitting in a public
repository is a live secret until it is rotated — automated bots scrape these
within minutes of a push.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .exposed_files import redact_env_values
from .registry import register

_PATTERNS: tuple[tuple[re.Pattern, Severity, str], ...] = (
    (
        re.compile(r"(^|/)\.env(\.|$)", re.IGNORECASE),
        Severity.CRITICAL,
        "environment file (likely contains live keys)",
    ),
    (
        re.compile(r"serviceaccountkey.*\.json$", re.IGNORECASE),
        Severity.CRITICAL,
        "Firebase service-account key",
    ),
    (
        re.compile(r"firebase-adminsdk.*\.json$", re.IGNORECASE),
        Severity.CRITICAL,
        "Firebase admin SDK key",
    ),
    (
        re.compile(r"(^|/)(id_rsa|id_ed25519)$", re.IGNORECASE),
        Severity.CRITICAL,
        "SSH private key",
    ),
    (
        re.compile(r"\.(pem|key)$", re.IGNORECASE),
        Severity.HIGH,
        "private key material",
    ),
    (
        re.compile(r"credentials\.json$", re.IGNORECASE),
        Severity.HIGH,
        "credentials file",
    ),
    (
        re.compile(r"(^|/)\.npmrc$", re.IGNORECASE),
        Severity.MEDIUM,
        "npm credentials (.npmrc)",
    ),
)

_REMEDIATION = (
    "Remove this file from the repository AND its git history, rotate every secret "
    "it contained, and add it to .gitignore so it can never be committed again."
)


@register
class RepoSensitiveFilesDetector(BaseDetector):
    id = "repo_sensitive_files"
    name = "Sensitive files committed to the repository"
    layer = 1
    # Repo-mode only: no probes, no network.

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for bundle in artifact.js_bundles:
            if urlsplit(bundle.url).scheme:
                continue  # URL-mode bundles are absolute URLs — this detector is repo-only
            for pattern, severity, label in _PATTERNS:
                if not pattern.search(bundle.url):
                    continue
                snippet = (
                    redact_env_values(bundle.content, 160)
                    if label.startswith("environment")
                    else "committed to the repository"
                )
                findings.append(
                    Finding(
                        detector_id=self.id,
                        category="exposed-sensitive-file",
                        cwe_id="CWE-538",
                        owasp_2025="A02:2025",
                        severity=severity,
                        confidence=0.9,
                        title=f"Sensitive file committed to repository: {bundle.url}",
                        evidence=[Evidence(url=bundle.url, snippet=snippet, detail=label)],
                        remediation_hint=_REMEDIATION,
                    )
                )
                break  # one finding per file
        return findings
