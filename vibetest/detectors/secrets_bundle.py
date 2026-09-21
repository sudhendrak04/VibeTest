"""Layer-2 detector: secrets leaked in client-side JS bundles.

Vibe-coded apps are notorious for pasting backend secrets into frontend bundles
(the service-role-key half of the CVE-2025-48757 pattern). This detector scans
downloaded bundle content for specific, high-confidence secret signatures —
deliberately NOT generic "looks like a key" heuristics, to keep precision high
(false positives destroy a security report's credibility).

Special case — Supabase JWTs: both the anon key and the service-role key are
JWTs that LOOK identical. The detector decodes each JWT found in a bundle and
inspects its `role` claim: `anon` keys are public BY DESIGN (no finding — they
are the intended client credential); `service_role` keys bypass all Row Level
Security (CRITICAL — this is the exact failure mode of CVE-2025-48757).

Evidence is always MASKED (first/last few characters kept) — the report never
republishes a usable secret.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact, JSBundle
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .jwt_tools import JWT_RE, jwt_role
from .registry import register

_MAX_EVIDENCE_PER_FINDING = 3


@dataclass(frozen=True)
class SecretPattern:
    id: str
    regex: re.Pattern
    severity: Severity
    title: str
    remediation: str


PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        id="supabase-secret-key",
        regex=re.compile(r"\bsb_secret_[A-Za-z0-9_-]{10,}\b"),
        severity=Severity.CRITICAL,
        title="Supabase secret key (sb_secret_) in client bundle",
        remediation="Rotate the key immediately in the Supabase dashboard and move any "
        "privileged operations into a server-side function. Secret keys bypass Row "
        "Level Security entirely and must never reach the browser.",
    ),
    SecretPattern(
        id="aws-access-key",
        regex=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity=Severity.CRITICAL,
        title="AWS access key ID in client bundle",
        remediation="Rotate the AWS access key in the IAM console right away and move "
        "AWS calls to a backend. Access keys in public bundles are picked up by "
        "automated scanners within minutes.",
    ),
    SecretPattern(
        id="stripe-live-key",
        regex=re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
        severity=Severity.CRITICAL,
        title="Stripe live secret key in client bundle",
        remediation="Roll the live key in the Stripe dashboard immediately. Payment "
        "operations belong on the server (or a Supabase Edge Function).",
    ),
    SecretPattern(
        id="stripe-test-key",
        regex=re.compile(r"\bsk_test_[A-Za-z0-9]{16,}\b"),
        severity=Severity.LOW,
        title="Stripe test key in client bundle",
        remediation="Test keys cannot move real money, but remove them anyway — they "
        "signal that live keys may follow the same pattern.",
    ),
    SecretPattern(
        id="github-pat",
        regex=re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
        severity=Severity.CRITICAL,
        title="GitHub personal access token in client bundle",
        remediation="Revoke the token on GitHub immediately (Settings → Developer "
        "settings) and move repository access to the server side.",
    ),
    SecretPattern(
        id="openai-project-key",
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_-]{20,}\b"),
        severity=Severity.CRITICAL,
        title="OpenAI project API key in client bundle",
        remediation="Rotate the key in the OpenAI dashboard and proxy AI calls through "
        "your backend — a leaked key means someone else runs up your bill.",
    ),
    SecretPattern(
        id="private-key",
        regex=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
        severity=Severity.CRITICAL,
        title="Private key material in client bundle",
        remediation="Treat this key as compromised: rotate it everywhere it is used, "
        "and never embed key files in frontend code.",
    ),
    SecretPattern(
        id="google-api-key",
        regex=re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        severity=Severity.HIGH,
        title="Google API key in client bundle",
        remediation="Google API keys are client-safe ONLY when restricted (HTTP referrer "
        "or API restrictions). Restrict the key in Google Cloud Console or move it "
        "server-side, and rotate it if it was unrestricted.",
    ),
    SecretPattern(
        id="slack-token",
        regex=re.compile(r"\bxox[bpars]-[0-9A-Za-z-]{10,}\b"),
        severity=Severity.CRITICAL,
        title="Slack token in client bundle",
        remediation="Revoke the token in the Slack app settings and move Slack calls to "
        "the server.",
    ),
    SecretPattern(
        id="sendgrid-key",
        regex=re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
        severity=Severity.CRITICAL,
        title="SendGrid API key in client bundle",
        remediation="Delete the key in SendGrid and send email from a server function. "
        "A leaked SendGrid key lets spammers send as your domain.",
    ),
)


def _mask(secret: str) -> str:
    if len(secret) <= 10:
        return secret[:2] + "***"
    return f"{secret[:6]}***{secret[-4:]}"


def _mask_context(content: str, match: re.Match) -> str:
    """Show a little surrounding code with the secret itself masked."""
    start, end = match.span()
    prefix = content[max(0, start - 40):start].replace("\n", " ")
    suffix = content[end:min(len(content), end + 20)].replace("\n", " ")
    return f"{prefix}{_mask(match.group(0))}{suffix}".strip()


@register
class SecretsBundleDetector(BaseDetector):
    id = "secrets_bundle"
    name = "Secrets in JS bundles"
    layer = 2
    # No probes needed: works purely on already-downloaded bundle content.

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for bundle in artifact.js_bundles:
            findings.extend(self._scan_bundle(bundle))
        return findings

    def _scan_bundle(self, bundle: JSBundle) -> list[Finding]:
        findings: list[Finding] = []

        for pattern in PATTERNS:
            matches = list(pattern.regex.finditer(bundle.content))[:_MAX_EVIDENCE_PER_FINDING]
            if not matches:
                continue
            findings.append(
                Finding(
                    detector_id=self.id,
                    category="secret-in-bundle",
                    cwe_id="CWE-798",
                    owasp_2025="A04:2025",
                    severity=pattern.severity,
                    confidence=0.9,
                    title=pattern.title,
                    evidence=[
                        Evidence(url=bundle.url, snippet=_mask_context(bundle.content, m))
                        for m in matches
                    ],
                    remediation_hint=pattern.remediation,
                )
            )

        # Supabase JWT role check — the CVE-2025-48757 pattern.
        service_tokens = [
            m for m in JWT_RE.finditer(bundle.content)
            if jwt_role(m.group(0)) == "service_role"
        ][:_MAX_EVIDENCE_PER_FINDING]
        if service_tokens:
            findings.append(
                Finding(
                    detector_id=self.id,
                    category="service-role-key-exposed",
                    cwe_id="CWE-798",
                    owasp_2025="A04:2025",
                    severity=Severity.CRITICAL,
                    confidence=0.95,  # deterministic: JWT payload decoded and role verified
                    title="Supabase service_role key in client bundle",
                    evidence=[
                        Evidence(url=bundle.url, snippet=_mask_context(bundle.content, m))
                        for m in service_tokens
                    ],
                    remediation_hint="Rotate this key in the Supabase dashboard immediately. "
                    "A service_role key bypasses ALL Row Level Security — anyone reading "
                    "this bundle can read and write every row in your database. Privileged "
                    "operations belong in server-side functions.",
                )
            )
        return findings
