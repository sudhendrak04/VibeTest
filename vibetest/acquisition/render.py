"""Headless-browser rendering for JavaScript-built pages (optional [crawl] extra).

Many vibe-coded apps deliver an almost-empty HTML shell and build the page with
JavaScript. Without rendering we only see the shell; with rendering we see the
DOM a real visitor gets — plus the scripts the page actually loads.

Safety rules:
- SOFT dependency: if `playwright` (or its browser) is not installed, this
  module returns nothing and the scanner keeps the raw HTML;
- EVERY request the browser makes is checked against the consent gate —
  non-allowlisted hosts are aborted inside the browser;
- images/fonts/media are skipped for speed (we only need DOM + scripts);
- rendering happens only for pages that LOOK like JS shells, capped per scan.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from importlib import util as importlib_util

from ..config import Settings
from ..core.consent import ConsentGate
from ..schemas.artifacts import PageSnapshot

logger = logging.getLogger(__name__)

_MIN_VISIBLE_TEXT = 300
_SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_EMPTY_ROOT_RE = re.compile(
    r"""<div[^>]+id=["'](root|app|__next|__nuxt)["'][^>]*>\s*</div>""", re.IGNORECASE
)

_SKIPPED_RESOURCE_TYPES = ("image", "font", "media")


@dataclass
class RenderedPage:
    html: str
    script_urls: list[str] = field(default_factory=list)


def is_available() -> bool:
    """True when the playwright package is importable (browser binary is checked at launch)."""
    return importlib_util.find_spec("playwright") is not None


def visible_text_length(html: str) -> int:
    without_scripts = _SCRIPT_RE.sub(" ", html)
    text = _TAG_RE.sub(" ", without_scripts)
    return len(" ".join(text.split()))


def looks_like_spa(page: PageSnapshot) -> bool:
    """True for sparse JS shells that need rendering to reveal the real page."""
    if _EMPTY_ROOT_RE.search(page.html):
        return True
    if "<script" not in page.html.lower():
        return False
    return visible_text_length(page.html) < _MIN_VISIBLE_TEXT


def should_block(url: str, resource_type: str, gate: ConsentGate) -> bool:
    """Browser traffic policy: the consent gate is authoritative."""
    if resource_type in _SKIPPED_RESOURCE_TYPES:
        return True
    return not gate.is_allowed(url)


def render_pages(
    urls: list[str], *, gate: ConsentGate, settings: Settings
) -> dict[str, RenderedPage]:
    """Render each URL headlessly. Returns {} when Playwright is unavailable."""
    if not urls:
        return {}
    if not is_available():
        logger.info('playwright not installed — using raw HTML (install with: pip install -e ".[crawl]" then playwright install chromium)')
        return {}
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:  # pragma: no cover — is_available() already checked
        return {}

    rendered: dict[str, RenderedPage] = {}
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(user_agent=settings.user_agent)
            page = context.new_page()
            observed_scripts: list[str] = []

            def _on_request(request) -> None:
                if request.resource_type == "script":
                    observed_scripts.append(request.url)

            def _route(route) -> None:
                request = route.request
                if should_block(request.url, request.resource_type, gate):
                    route.abort()
                else:
                    route.continue_()

            page.on("request", _on_request)
            page.route("**/*", _route)

            for url in urls[: settings.max_render_pages]:
                observed_scripts.clear()
                try:
                    page.goto(url, wait_until="networkidle", timeout=settings.render_timeout * 1000)
                except PlaywrightTimeoutError:
                    pass  # page kept loading — capture whatever rendered so far
                except Exception as exc:  # noqa: BLE001 — never fail a scan because of rendering
                    logger.warning("rendering failed for %s (%s) — keeping raw HTML", url, exc)
                    continue
                rendered[url] = RenderedPage(
                    html=page.content(), script_urls=list(observed_scripts)
                )
            browser.close()
    except Exception as exc:  # noqa: BLE001 — e.g. browser binary not installed
        logger.warning("headless rendering unavailable (%s) — using raw HTML", exc)
        return {}
    return rendered
