"""Layer-2 detector: Supabase Row Level Security (RLS) misconfiguration.

The CVE-2025-48757 pattern: Supabase exposes every table through a public REST
API (PostgREST), and the anon key that authorizes those calls is PUBLIC by
design — it ships inside the browser bundle. The ONLY thing standing between a
stranger and your data is Row Level Security. When RLS is missing (or permissive,
e.g. `using (true)`), anyone can read every row with the site's own public key.

How this detector works:
1. Finds the Supabase project URL + public (anon / publishable) key in the
   already-downloaded JS bundles.
2. Asks the REST API which tables exist (PostgREST's OpenAPI root).
3. Fetches at most ONE row per table using ONLY the public anon key.
   - rows returned            → table readable without a session → CRITICAL
   - `[]` returned            → ambiguous (empty table OR RLS working) → no finding
   - 401/403                  → protected → no finding

READ-ONLY by design: never INSERT/UPDATE/DELETE, never a write probe.
Evidence shows row count + column names only — never actual row values.
Every probe is consent-gated; non-allowlisted Supabase hosts are skipped.
"""
from __future__ import annotations

import json
import logging
import re

import httpx

from ..core.context import ScanContext
from ..core.http_util import read_bounded
from ..schemas.artifacts import Artifact, JSBundle
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .jwt_tools import JWT_RE, jwt_role
from .registry import register

logger = logging.getLogger(__name__)

_MAX_READ = 65536
_MAX_TABLES = 10

_PROJECT_URL_RE = re.compile(r"https://[a-z0-9-]+\.supabase\.co", re.IGNORECASE)
_ASSIGN_URL_RE = re.compile(
    r"""(?i)(?:supabase[_-]?url)\s*[:=]\s*["'](https?://[^"'\s]+)["']"""
)
_PUBLISHABLE_KEY_RE = re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{10,}\b")

_SENSITIVE_COLUMNS = {
    "email", "phone", "password", "token", "address", "card", "ssn", "dob", "api_key",
}


@register
class SupabaseRLSDetector(BaseDetector):
    id = "supabase_rls"
    name = "Supabase RLS misconfiguration"
    layer = 2
    needs_probes = True  # extra GET requests via ctx.http — always consent-gated

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None:
            return []

        candidates: dict[str, str | None] = {}
        for bundle in artifact.js_bundles:
            for base, key in self._extract_candidates(bundle):
                if base not in candidates or candidates[base] is None:
                    candidates[base] = key

        findings: list[Finding] = []
        for base, key in candidates.items():
            if key is None:
                continue  # no public key found → cannot test RLS responsibly
            rest_root = base.rstrip("/") + "/rest/v1/"
            if not ctx.gate.is_allowed(rest_root):
                logger.info("supabase host not allowlisted, skipping probe: %s", base)
                continue  # consent gate is authoritative
            findings.extend(self._check_project(ctx.http, rest_root, key))
        return findings

    @staticmethod
    def _extract_candidates(bundle: JSBundle) -> list[tuple[str, str | None]]:
        content = bundle.content
        bases = set(_PROJECT_URL_RE.findall(content))
        bases.update(_ASSIGN_URL_RE.findall(content))
        if not bases:
            return []
        keys = [m.group(0) for m in JWT_RE.finditer(content) if jwt_role(m.group(0)) == "anon"]
        keys.extend(_PUBLISHABLE_KEY_RE.findall(content))
        first_key = keys[0] if keys else None
        return [(b, first_key) for b in sorted(bases)]

    def _check_project(self, client, rest_root: str, key: str) -> list[Finding]:
        headers = {"apikey": key, "Authorization": f"Bearer {key}"}
        tables = self._list_tables(client, rest_root, headers)
        findings: list[Finding] = []
        for table in tables[:_MAX_TABLES]:
            finding = self._probe_table(client, rest_root, table, headers)
            if finding is not None:
                findings.append(finding)
        return findings

    @staticmethod
    def _list_tables(client, rest_root: str, headers: dict) -> list[str]:
        try:
            with client.stream("GET", rest_root, headers=headers) as resp:
                if resp.status_code != 200:
                    return []
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return []
        try:
            spec = json.loads(raw)
        except ValueError:
            return []
        tables: list[str] = []
        for path in spec.get("paths") or {}:
            name = str(path).strip("/")
            if name and "/" not in name:
                tables.append(name)
        return tables

    def _probe_table(self, client, rest_root: str, table: str, headers: dict) -> Finding | None:
        url = f"{rest_root}{table}?select=*&limit=1"
        try:
            with client.stream("GET", url, headers=headers) as resp:
                status = resp.status_code
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return None
        if status != 200:
            return None  # protected (401/403) or missing (404) — not a finding
        try:
            rows = json.loads(raw)
        except ValueError:
            return None
        if not isinstance(rows, list) or not rows:
            # `[]` is ambiguous: empty table OR RLS doing its job → precision-first, skip.
            return None

        sample = rows[0]
        columns = sorted(sample.keys()) if isinstance(sample, dict) else []
        sensitive = sorted({c.lower() for c in columns} & _SENSITIVE_COLUMNS)

        bits = [f"returned {len(rows)} row(s)"]
        if columns:
            bits.append(f"columns: {', '.join(columns[:10])}")
        if sensitive:
            bits.append(f"sensitive fields present: {', '.join(sensitive)}")

        return Finding(
            detector_id=self.id,
            category="supabase-rls-missing",
            cwe_id="CWE-862",
            owasp_2025="A01:2025",
            severity=Severity.CRITICAL,
            confidence=0.9,
            title=f"Supabase table readable without a session: {table}",
            evidence=[
                Evidence(
                    url=url,
                    snippet="; ".join(bits),  # counts + column names only — never row values
                    detail="fetched with only the public anon key taken from the site's own bundle",
                )
            ],
            remediation_hint=(
                "Enable Row Level Security on this table and add owner-scoped policies "
                "(e.g. `using (auth.uid() = user_id)`). RLS is the ONLY protection for "
                "data behind the public anon key — this exact pattern (CVE-2025-48757) "
                "exposed 170+ apps built with AI app builders."
            ),
        )
