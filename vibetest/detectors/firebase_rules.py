"""Layer-2 detector: open Firebase Realtime Database Security Rules.

The Firebase sibling of the Supabase RLS misconfiguration: the database URL
ships inside the client bundle by design, and when the Security Rules allow
public reads, one unauthenticated request returns the whole database
(`https://<project>-default-rtdb.firebaseio.com/.json`).

Scope: Realtime Database only for now — Firestore checks need collection-name
discovery (future work).

Read-only: a single GET per candidate database root, bounded read. Precision:
- data returned       → CRITICAL finding
- `null` returned     → public read is allowed but the database is empty → MEDIUM
- Permission denied   → not a finding
Every probe is consent-gated; a real Firebase host must be on the allowlist.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlsplit

import httpx

from ..core.context import ScanContext
from ..core.http_util import looks_like_html, read_bounded
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

logger = logging.getLogger(__name__)

_MAX_READ = 262_144
_MAX_CANDIDATES = 3

_DATABASE_URL_RE = re.compile(
    r"""databaseURL["']?\s*[:=]\s*["'](https?://[^"'\s]+)["']""", re.IGNORECASE
)
_FIREBASE_HOST_RE = re.compile(
    r"https://[a-z0-9-]+\.firebaseio\.com|https://[a-z0-9-]+(?:\.[a-z0-9-]+)?\.firebasedatabase\.app",
    re.IGNORECASE,
)

_REMEDIATION = (
    "Set Firebase Security Rules so public access is denied (e.g. `{\".read\": false, "
    "\".write\": false}` at the root, or auth-based rules). The database URL is public "
    "by design — the rules are the only protection. Consider enabling App Check too."
)


@register
class FirebaseRulesDetector(BaseDetector):
    id = "firebase_rules"
    name = "Open Firebase database rules"
    layer = 2
    needs_probes = True  # extra GET requests via ctx.http — always consent-gated

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None:
            return []
        findings: list[Finding] = []
        for base in self._extract_candidates(artifact)[:_MAX_CANDIDATES]:
            url = base.rstrip("/") + "/.json"
            if not ctx.gate.is_allowed(url):
                continue  # consent gate is authoritative
            finding = self._probe(ctx.http, url, base)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _extract_candidates(artifact: Artifact) -> list[str]:
        found: set[str] = set()
        haystacks = [p.html for p in artifact.pages] + [b.content for b in artifact.js_bundles]
        for hay in haystacks:
            found.update(_DATABASE_URL_RE.findall(hay))
            found.update(_FIREBASE_HOST_RE.findall(hay))
        return sorted(found)

    def _probe(self, client, url: str, base: str) -> Finding | None:
        try:
            with client.stream("GET", url) as resp:
                status = resp.status_code
                content_type = resp.headers.get("content-type", "")
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return None
        if status != 200 or looks_like_html(content_type, raw):
            return None  # denied (401/403), missing, or an HTML decoy

        host = urlsplit(base).hostname or base
        body = raw.strip()

        if body == b"null":
            # Security Rules permit public reads; the database is just empty right now.
            return Finding(
                detector_id=self.id,
                category="firebase-rules-open",
                cwe_id="CWE-862",
                owasp_2025="A01:2025",
                severity=Severity.MEDIUM,
                confidence=0.85,
                title=f"Firebase database allows public read (currently empty): {host}",
                evidence=[
                    Evidence(
                        url=url,
                        snippet="`/.json` returned null without credentials — Security Rules permit public reads",
                    )
                ],
                remediation_hint=_REMEDIATION,
            )

        if not (body.startswith(b"{") or body.startswith(b"[")) or b'"error"' in body[:200]:
            return None  # error payload or unexpected body — not a finding

        keys: list[str] = []
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                keys = sorted(str(k) for k in parsed)[:8]
        except ValueError:
            pass  # large/truncated document — still clearly readable data

        snippet = "returned data without credentials"
        if keys:
            snippet += f"; top-level keys: {', '.join(keys)}"

        return Finding(
            detector_id=self.id,
            category="firebase-rules-open",
            cwe_id="CWE-862",
            owasp_2025="A01:2025",
            severity=Severity.CRITICAL,
            confidence=0.9,
            title=f"Firebase database readable without authentication: {host}",
            evidence=[Evidence(url=url, snippet=snippet)],
            remediation_hint=_REMEDIATION,
        )
