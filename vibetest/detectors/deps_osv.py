"""Layer-1 detector: vulnerable dependencies via the free OSV database.

Vibe-coded apps routinely ship with outdated packages. This detector:
1. probes a small set of well-known manifest paths (/package-lock.json,
   /yarn.lock, /pnpm-lock.yaml, /package.json) — these are never meant to be
   public on a website;
2. extracts exact package@version pairs from whatever it finds;
3. asks the OSV.dev API (free, no key — the same vulnerability database behind
   `osv-scanner`) about each package and reports known advisories
   (CVE / GHSA ids included).

Notes:
- OSV.dev is an external vulnerability DATABASE service, not a scan target:
  the consent gate governs requests to the scanned site only. The API URL is
  configurable (`osv_api_url`) and can be disabled by setting it to "".
- Only EXACT versions are checked (`^1.2.3` ranges cannot be resolved reliably).
- Read-only; evidence contains versions + advisory ids, nothing else.
"""
from __future__ import annotations

import json
import logging
import re
from urllib.parse import urlsplit

import httpx
import yaml

from ..core.context import ScanContext
from ..core.http_util import looks_like_html, read_bounded
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

logger = logging.getLogger(__name__)

_MAX_READ = 2_000_000
_MANIFEST_PATHS = ("/package-lock.json", "/yarn.lock", "/pnpm-lock.yaml", "/package.json")
_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_YARN_BLOCK_RE = re.compile(r'^(.+?):\n(?:.*\n)*?[ \t]+version "([^"]+)"', re.MULTILINE)

_SEVERITY_BY_LABEL = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _target_base(artifact: Artifact) -> str | None:
    url = artifact.pages[0].url if artifact.pages else artifact.target_url
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _dedupe(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return sorted(dict.fromkeys(pairs))


# ---------------------------------------------------------------- parsers

def _parse_package_lock(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    pairs: list[tuple[str, str]] = []

    packages = data.get("packages")  # npm v2/v3
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict) or "node_modules/" not in key:
                continue
            name = key.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and isinstance(version, str):
                pairs.append((name, version))

    def walk(deps) -> None:  # npm v1 (recursive)
        if not isinstance(deps, dict):
            return
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            if isinstance(version, str):
                pairs.append((name, version))
            walk(meta.get("dependencies"))

    walk(data.get("dependencies"))
    return pairs


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    if not isinstance(data, dict):
        return []
    pairs: list[tuple[str, str]] = []
    for field in ("dependencies", "devDependencies"):
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, version in deps.items():
            if isinstance(version, str) and _EXACT_VERSION_RE.match(version):
                pairs.append((name, version))
    return pairs


def _parse_yarn_lock(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for names_blob, version in _YARN_BLOCK_RE.findall(text):
        for spec in names_blob.split(","):
            spec = spec.strip().strip('"')
            if not spec or spec.startswith("#"):
                continue
            idx = spec.rfind("@")
            name = spec[:idx] if idx > 0 else spec
            if name:
                pairs.append((name, version))
    return pairs


def _parse_pnpm_lock(text: str) -> list[tuple[str, str]]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(data, dict):
        return []
    pairs: list[tuple[str, str]] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key in packages:
            if not isinstance(key, str):
                continue
            spec = key.lstrip("/").split("(")[0]  # strip peer-dependency suffix
            idx = spec.rfind("@")
            if idx <= 0:
                continue
            name, version = spec[:idx], spec[idx + 1:]
            if name and version:
                pairs.append((name, version))
    return pairs


def parse_manifest(path: str, text: str) -> list[tuple[str, str]]:
    """Dispatch to the right parser for a manifest path. Returns (name, version) pairs."""
    if path.endswith("package-lock.json"):
        return _parse_package_lock(text)
    if path.endswith("yarn.lock"):
        return _parse_yarn_lock(text)
    if path.endswith("pnpm-lock.yaml"):
        return _parse_pnpm_lock(text)
    if path.endswith("package.json"):
        return _parse_package_json(text)
    return []


# ---------------------------------------------------------------- OSV queries

def query_osv(client, api_url: str, name: str, version: str, ecosystem: str = "npm") -> list[dict]:
    """Ask the free OSV.dev database about one package@version. Returns [] on any failure."""
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        with client.stream("POST", api_url, json=payload) as resp:
            if resp.status_code != 200:
                return []
            raw = read_bounded(resp, _MAX_READ)  # OSV responses can exceed 200 KB (e.g. axios)
    except httpx.HTTPError:
        return []
    try:
        data = json.loads(raw)
    except ValueError:
        return []
    vulns = data.get("vulns") if isinstance(data, dict) else None
    return vulns if isinstance(vulns, list) else []


def _vuln_severity(vuln: dict) -> Severity:
    label = ""
    ds = vuln.get("database_specific")
    if isinstance(ds, dict):
        label = str(ds.get("severity", ""))
    return _SEVERITY_BY_LABEL.get(label.upper(), Severity.MEDIUM)


def _advisory_ids(vulns: list[dict]) -> list[str]:
    ids: list[str] = []
    for vuln in vulns:
        for candidate in [vuln.get("id"), *(vuln.get("aliases") or [])]:
            if isinstance(candidate, str) and candidate and candidate not in ids:
                ids.append(candidate)
    return ids[:8]


@register
class DepsOSVDetector(BaseDetector):
    id = "deps_osv"
    name = "Vulnerable dependencies"
    layer = 1
    needs_probes = True  # extra GET requests via ctx.http — always consent-gated

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None:
            return []
        base = _target_base(artifact)
        if base is None:
            return []

        findings: list[Finding] = []
        for path in _MANIFEST_PATHS:
            url = base + path
            if not ctx.gate.is_allowed(url):
                continue  # consent gate is authoritative
            text = self._fetch_manifest(ctx.http, url)
            if text is None:
                continue
            pairs = _dedupe(parse_manifest(path, text))
            if not pairs:
                continue
            findings.append(
                Finding(
                    detector_id=self.id,
                    category="exposed-sensitive-file",
                    cwe_id="CWE-538",
                    owasp_2025="A02:2025",
                    severity=Severity.LOW,
                    confidence=0.95,
                    title=f"Dependency manifest publicly accessible: {path}",
                    evidence=[
                        Evidence(
                            url=url,
                            snippet=f"{len(pairs)} package version(s) disclosed "
                            f"(e.g. {', '.join(f'{n}@{v}' for n, v in pairs[:3])})",
                        )
                    ],
                    remediation_hint=(
                        "Remove dependency manifests from the deployed site — they are not "
                        "needed at runtime and disclose your exact dependency versions."
                    ),
                )
            )
            if ctx.settings.osv_api_url:
                findings.extend(self._check_packages(ctx, url, pairs))
        return findings

    @staticmethod
    def _fetch_manifest(client, url: str) -> str | None:
        try:
            with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return None
                content_type = resp.headers.get("content-type", "")
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return None
        if looks_like_html(content_type, raw):
            return None  # SPA fallback shell, not a manifest
        return raw.decode("utf-8", errors="replace")

    def _check_packages(self, ctx: ScanContext, manifest_url: str, pairs: list[tuple[str, str]]) -> list[Finding]:
        findings: list[Finding] = []
        for name, version in pairs[: ctx.settings.osv_max_packages]:
            vulns = query_osv(ctx.http, ctx.settings.osv_api_url, name, version)
            if not vulns:
                continue
            severity = max((_vuln_severity(v) for v in vulns), key=_SEVERITY_ORDER.index)
            ids = _advisory_ids(vulns)
            count = len(vulns)
            summary = str(vulns[0].get("summary") or "")[:140]
            findings.append(
                Finding(
                    detector_id=self.id,
                    category="vulnerable-dependency",
                    cwe_id="CWE-1104",
                    owasp_2025="A03:2025",
                    severity=severity,
                    confidence=0.9,
                    title=(
                        f"Vulnerable dependency: {name}@{version} "
                        f"({count} known advisor{'y' if count == 1 else 'ies'})"
                    ),
                    evidence=[
                        Evidence(
                            url=manifest_url,
                            snippet=f"advisories: {', '.join(ids)}" + (f" — {summary}" if summary else ""),
                            detail="source: OSV.dev (free vulnerability database)",
                        )
                    ],
                    remediation_hint=(
                        f"Update {name} to a fixed version and redeploy. Also remove the "
                        "manifest from the public site. See the advisory ids above for details."
                    ),
                )
            )
        return findings
