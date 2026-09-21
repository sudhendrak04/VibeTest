"""Week 4 — JS bundle extraction from already-fetched pages.

Parses `<script src>` tags from each fetched page's HTML, resolves them to
absolute URLs, and downloads the app's OWN bundles (allowlisted hosts only —
third-party CDN scripts are libraries, not app code, and outside our consent
scope; this is also where vibe-coded app secrets actually live).

Also captures `//# sourceMappingURL=...` references for the source-map detector.

Browser-rendered pages are handled in render.py: their rendered DOM (script tags
injected by JavaScript) and observed script requests feed this module via
`extra_urls`. Static extraction alone already covers many Next.js/React builds
because their script tags appear in the delivered HTML.
"""
from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from ..core.context import ScanContext
from ..core.http_util import read_bounded
from ..schemas.artifacts import JSBundle, PageSnapshot

logger = logging.getLogger(__name__)

_MAX_BUNDLE_BYTES = 2_000_000  # never download more than 2 MB per bundle
_SOURCEMAP_RE = re.compile(r"sourceMappingURL=([^\s'\"]+)")


class _ScriptSrcCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.script_srcs: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            for name, value in attrs:
                if name == "src" and value:
                    self.script_srcs.append(value.strip())


def script_srcs(html: str) -> list[str]:
    """Collect <script src> values. Malformed HTML is skipped, never fatal."""
    collector = _ScriptSrcCollector()
    try:
        collector.feed(html)
        collector.close()
    except Exception:
        pass
    return collector.script_srcs


def extract_sourcemap_url(bundle_url: str, content: str) -> str | None:
    """Find a `//# sourceMappingURL=...` comment (usually the file's last line)."""
    tail = content[-512:]
    m = _SOURCEMAP_RE.search(tail)
    if not m:
        return None
    return urljoin(bundle_url, m.group(1))


def extract_bundles(
    pages: list[PageSnapshot],
    ctx: ScanContext,
    client: httpx.Client | None = None,
    extra_urls: list[str] | None = None,
) -> list[JSBundle]:
    """Collect unique script URLs (page HTML + browser-observed extras) and
    download the app's own bundles."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _admit(url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return  # data:/blob: scripts are not downloadable bundles
        if url in seen:
            return
        seen.add(url)
        if not ctx.gate.is_allowed(url):
            return  # consent scope: allowlisted-host bundles only
        candidates.append(url)

    for page in pages:
        for src in script_srcs(page.html):
            _admit(urljoin(page.url, src))
    for url in extra_urls or []:
        _admit(url)  # scripts observed by the headless browser (render.py)

    if not candidates:
        return []

    bundles: list[JSBundle] = []
    owns_client = client is None
    if client is None:
        client = httpx.Client(
            follow_redirects=True,
            timeout=ctx.settings.request_timeout,
            headers={"User-Agent": ctx.settings.user_agent},
        )
    try:
        for url in candidates:
            try:
                with client.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        continue
                    if "text/html" in resp.headers.get("content-type", "").lower():
                        continue  # SPA fallback shell, not a script
                    raw = read_bounded(resp, _MAX_BUNDLE_BYTES)
            except httpx.HTTPError as exc:
                logger.info("bundle fetch failed for %s: %s", url, exc)
                continue
            text = raw.decode("utf-8", errors="replace")
            bundles.append(
                JSBundle(
                    url=url,
                    content=text,
                    source_map_url=extract_sourcemap_url(url, text),
                )
            )
    finally:
        if owns_client:
            client.close()
    return bundles
