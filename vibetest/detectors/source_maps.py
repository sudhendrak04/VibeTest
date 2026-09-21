"""Layer-2 detector: publicly accessible JavaScript source maps.

Production bundles often carry a `//# sourceMappingURL=app.js.map` comment (our
bundle extractor captures it), and static hosts happily serve the `.map` file
too. A public source map lets anyone reconstruct the ORIGINAL source code —
comments, internal module structure, sometimes the full embedded source.

Checks both the explicit `sourceMappingURL` reference and the `.js.map`
convention, with bounded reads (2 MB) and signature validation, so SPA hosts
answering 200-with-the-app-shell for any path cannot cause false positives.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import urlsplit

import httpx

from ..core.context import ScanContext
from ..core.http_util import looks_like_html, read_bounded
from ..schemas.artifacts import Artifact, JSBundle
from ..schemas.findings import Evidence, Finding, Severity
from .base import BaseDetector
from .registry import register

logger = logging.getLogger(__name__)

_MAX_READ = 2_000_000
_MAX_PROBES = 10


@register
class SourceMapsDetector(BaseDetector):
    id = "source_maps"
    name = "Exposed source maps"
    layer = 2
    needs_probes = True  # extra GET requests via ctx.http — always consent-gated

    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]:
        if ctx.http is None:
            return []
        findings: list[Finding] = []
        probed: set[str] = set()
        for bundle in artifact.js_bundles:
            candidates: list[str] = []
            if bundle.source_map_url:
                candidates.append(bundle.source_map_url)
            elif bundle.url.endswith((".js", ".mjs")):
                candidates.append(bundle.url + ".map")  # convention even without a comment
            for url in candidates:
                if url in probed:
                    continue
                if len(probed) >= _MAX_PROBES:
                    return findings
                probed.add(url)
                if not ctx.gate.is_allowed(url):
                    continue  # consent gate is authoritative
                finding = self._probe(ctx.http, url, bundle)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _probe(self, client, url: str, bundle: JSBundle) -> Finding | None:
        try:
            with client.stream("GET", url) as resp:
                status = resp.status_code
                content_type = resp.headers.get("content-type", "")
                raw = read_bounded(resp, _MAX_READ)
        except httpx.HTTPError:
            return None
        if status != 200 or looks_like_html(content_type, raw):
            return None

        data: dict | None = None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                data = parsed
        except ValueError:
            data = None

        if data is not None:
            if "mappings" not in data and "sources" not in data:
                return None  # valid JSON, but not a source map
            sources = data.get("sources")
            count = len(sources) if isinstance(sources, list) else 0
            names = ", ".join(str(s) for s in sources[:3]) if count else ""
            snippet = f"valid source map: {count} source file(s) recoverable"
            if names:
                snippet += f" (e.g. {names})"
        else:
            # The read may have been capped on a very large map — accept only a
            # clear source-map JSON shape (starts with '{' and has "sources").
            if not raw.lstrip().startswith(b"{") or b'"sources"' not in raw:
                return None
            snippet = "large source map detected (read capped at 2 MB)"

        return Finding(
            detector_id=self.id,
            category="source-map-exposed",
            cwe_id="CWE-200",
            owasp_2025="A02:2025",
            severity=Severity.LOW,
            confidence=0.9,
            title=f"Source map publicly accessible: {urlsplit(url).path}",
            evidence=[Evidence(url=url, snippet=snippet, detail=f"referenced by {bundle.url}")],
            remediation_hint=(
                "Disable source-map generation for production builds (`build.sourcemap: "
                "false`, or upload maps privately to your error-tracking service). Public "
                "maps let anyone reconstruct your original source code."
            ),
        )
