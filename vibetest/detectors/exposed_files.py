"""Layer-1 detector: exposed sensitive files.

Checks a small fixed list of well-known paths (.env variants, .git internals,
SQL dumps, config.json, .DS_Store) with gentle GET probes: no redirects, at most
4 KB read per path, and content-signature validation.

Why content validation matters: SPA hosts (Vercel/Netlify/…) answer HTTP 200 with
the app shell for *every* unknown path — a bare status-code check would report
every target as leaking everything. A candidate counts as exposed only if the
body also matches the expected file signature.

Every probe URL is re-checked by the consent gate before any request is made.
Secrets found in .env-style files are REDACTED in evidence (keys kept, values
masked) — the report never re-publishes the leak itself.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from ..core.context import ScanContext
from ..core.http_util import looks_like_html, read_bounded
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

_MAX_READ = 4096

_ENV_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*=.", re.MULTILINE)
_GIT_HEAD = re.compile(r"^(ref:\s+refs/\S*|[0-9a-f]{40})\s*$")
_SQL_MARKER = re.compile(r"(INSERT INTO|CREATE TABLE|--\s*(MySQL|PostgreSQL|Dump))", re.IGNORECASE)


@dataclass(frozen=True)
class ProbeSpec:
    path: str
    kind: str  # env | git_head | git_config | sql | json | ds_store
    severity: Severity
    remediation: str


PROBES: tuple[ProbeSpec, ...] = (
    ProbeSpec(
        "/.env", "env", Severity.CRITICAL,
        "Remove this file from the deployed site (and every public location) and rotate "
        "any keys it contained. Environment variables belong in your host's secret "
        "settings, never in files the site serves.",
    ),
    ProbeSpec(
        "/.env.local", "env", Severity.CRITICAL,
        "Remove this file from the deployed site and rotate any keys it contained. Keep "
        "environment files out of the public build output.",
    ),
    ProbeSpec(
        "/.env.production", "env", Severity.CRITICAL,
        "Remove this file from the deployed site and rotate any keys it contained. Keep "
        "environment files out of the public build output.",
    ),
    ProbeSpec(
        "/.env.development", "env", Severity.CRITICAL,
        "Remove this file from the deployed site and rotate any keys it contained. Keep "
        "environment files out of the public build output.",
    ),
    ProbeSpec(
        "/.git/HEAD", "git_head", Severity.CRITICAL,
        "Block access to the .git directory (most hosts offer a setting or a one-line "
        "config). If it was reachable, treat the source code and any secrets in its "
        "history as leaked.",
    ),
    ProbeSpec(
        "/.git/config", "git_config", Severity.CRITICAL,
        "Block access to the .git directory. An exposed repository lets anyone download "
        "your full source code and its history.",
    ),
    ProbeSpec(
        "/backup.sql", "sql", Severity.CRITICAL,
        "Remove the database dump from the public site immediately — it likely contains "
        "real user data. Keep backups outside the web root and rotate any credentials.",
    ),
    ProbeSpec(
        "/database.sql", "sql", Severity.CRITICAL,
        "Remove the database dump from the public site immediately — it likely contains "
        "real user data. Keep backups outside the web root and rotate any credentials.",
    ),
    ProbeSpec(
        "/dump.sql", "sql", Severity.CRITICAL,
        "Remove the database dump from the public site immediately — it likely contains "
        "real user data. Keep backups outside the web root and rotate any credentials.",
    ),
    ProbeSpec(
        "/config.json", "json", Severity.MEDIUM,
        "Move configuration to server-side environment variables. If the file must stay "
        "public, remove any keys, passwords or tokens from it.",
    ),
    ProbeSpec(
        "/.DS_Store", "ds_store", Severity.LOW,
        "Delete macOS metadata files before deploying — they can reveal internal folder "
        "and file names.",
    ),
)


def _base_url(artifact: Artifact) -> str | None:
    url = artifact.pages[0].url if artifact.pages else artifact.target_url
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _matches_signature(kind: str, text: str, raw: bytes) -> bool:
    if kind == "env":
        return bool(_ENV_LINE.search(text))
    if kind == "git_head":
        return bool(_GIT_HEAD.match(text.strip()))
    if kind == "git_config":
        return "[core]" in text or "[remote " in text
    if kind == "sql":
        return bool(_SQL_MARKER.search(text))
    if kind == "ds_store":
        return raw.startswith(b"\x00\x00\x00\x01Bud1")
    if kind == "json":
        try:
            json.loads(text)
        except ValueError:
            return False
        return True
    return False


def redact_env_values(text: str, limit: int = 240) -> str:
    """Mask secret VALUES in env-style text — keys stay visible, values become ***."""
    lines = []
    for line in text.splitlines()[:8]:
        if "=" in line and not line.lstrip().startswith("#"):
            key, _, _ = line.partition("=")
            lines.append(f"{key}=***")
        else:
            lines.append(line)
    return "\n".join(lines).strip()[:limit]


def _redact(text: str, kind: str, limit: int = 240) -> str:
    """Mask secret VALUES in evidence — keys stay visible, values become ***."""
    if kind == "env":
        return redact_env_values(text, limit)
    return text.strip()[:limit]


@register
class ExposedFilesDetector(BaseDetector):
    id = "exposed_files"
    name = "Exposed sensitive files"
    layer = 1
    needs_probes = True  # extra GET requests via ctx.http — always consent-gated

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None:
            return []
        base = _base_url(artifact)
        if base is None:
            return []

        findings: list[Finding] = []
        for spec in PROBES:
            url = base + spec.path
            if not ctx.gate.is_allowed(url):
                continue  # consent gate is authoritative — no request without it
            finding = self._probe(ctx.http, url, spec)
            if finding is not None:
                findings.append(finding)
        return findings

    def _probe(self, client, url: str, spec: ProbeSpec) -> Finding | None:
        try:
            with client.stream("GET", url) as resp:
                status = resp.status_code
                content_type = resp.headers.get("content-type", "")
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return None  # unreachable endpoint — not a finding
        if status != 200:
            return None  # 403/404/redirects are all "not exposed"

        text = raw.decode("utf-8", errors="replace")
        if looks_like_html(content_type, raw) or not _matches_signature(spec.kind, text, raw):
            return None  # SPA fallback shell, or content we cannot verify — not a finding

        return Finding(
            detector_id=self.id,
            category="exposed-sensitive-file",
            cwe_id="CWE-538",
            owasp_2025="A02:2025",
            severity=spec.severity,
            confidence=0.9,
            title=f"Exposed sensitive file: {spec.path}",
            evidence=[
                Evidence(
                    url=url,
                    snippet=_redact(text, spec.kind),
                    detail=f"HTTP 200, content verified as {spec.kind}",
                )
            ],
            remediation_hint=spec.remediation,
        )
