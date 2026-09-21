"""Layer-1 detector (repo mode): vulnerable dependencies from committed lockfiles.

Reads the repository's own lockfiles (package-lock.json / yarn.lock /
pnpm-lock.yaml) and asks the free OSV.dev service about each package. No
requests are made to the deployed site — ctx.http is used only for the OSV
service, and only when `osv_api_url` is enabled.
"""
from __future__ import annotations

from urllib.parse import urlsplit

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
# Reuse the URL-mode dependency helpers (parsers, OSV query, severity mapping).
from .deps_osv import _advisory_ids, _vuln_severity, parse_manifest, query_osv
from .registry import register

_LOCKFILE_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


@register
class RepoDepsDetector(BaseDetector):
    id = "repo_deps"
    name = "Vulnerable dependencies (repository lockfiles)"
    layer = 1
    # No target probes: reads lockfiles from the repo artifact.

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None or not ctx.settings.osv_api_url:
            return []
        findings: list[Finding] = []
        budget = ctx.settings.osv_max_packages
        for bundle in artifact.js_bundles:
            if urlsplit(bundle.url).scheme:
                continue  # repo files only
            filename = bundle.url.rsplit("/", 1)[-1]
            if filename not in _LOCKFILE_NAMES:
                continue
            for name, version in parse_manifest("/" + filename, bundle.content):
                if budget <= 0:
                    return findings
                budget -= 1
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
                                url=bundle.url,
                                snippet=f"advisories: {', '.join(ids)}"
                                + (f" — {summary}" if summary else ""),
                                detail="source: OSV.dev (free vulnerability database)",
                            )
                        ],
                        remediation_hint=(
                            f"Update {name} to a fixed version, regenerate the lockfile and "
                            "redeploy. See the advisory ids above for details."
                        ),
                    )
                )
        return findings
