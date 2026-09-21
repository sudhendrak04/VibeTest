"""Crawler. Katana discovery (soft dependency) + httpx fetching + JS bundle extraction.

Flow: consent-gated Katana discovery → fetch entry page + discovered pages (capped)
→ render JS-built pages in a headless browser when Playwright is installed
(see render.py) → download the app's own JS bundles → Artifact. If Katana or
Playwright are missing, the scan degrades gracefully and still produces an Artifact.
"""
from __future__ import annotations

import logging

import httpx

from ..core.context import ScanContext
from ..schemas.artifacts import Artifact, Endpoint, PageSnapshot
from . import fingerprint, katana, render
from .js_bundle import extract_bundles

logger = logging.getLogger(__name__)


def select_urls(entry_url: str, discovered: list[katana.DiscoveredURL], max_pages: int) -> list[str]:
    """Entry page first, then discovered URLs (deduped, capped). Pure — unit-tested."""
    urls = [entry_url]
    seen = {entry_url}
    for d in discovered:
        if len(urls) >= max_pages:
            break
        if d.url in seen:
            continue
        seen.add(d.url)
        urls.append(d.url)
    return urls


def _apply_rendering(pages: list[PageSnapshot], ctx: ScanContext) -> list[str]:
    """Render SPA-looking pages when Playwright is installed.

    Replaces raw shell HTML with the rendered DOM and returns the script URLs
    the browser observed (they feed bundle extraction). Pure side-effect-free
    when rendering is disabled or unavailable.
    """
    if not ctx.settings.render_spa:
        return []
    candidates = [p.url for p in pages if render.looks_like_spa(p)][: ctx.settings.max_render_pages]
    if not candidates:
        return []
    rendered = render.render_pages(candidates, gate=ctx.gate, settings=ctx.settings)
    extra_scripts: list[str] = []
    for page in pages:
        rendered_page = rendered.get(page.url)
        if rendered_page is None:
            continue
        page.html = rendered_page.html
        extra_scripts.extend(rendered_page.script_urls)
    return extra_scripts


def fetch(url: str, ctx: ScanContext) -> Artifact:
    """Discover URLs (Katana), fetch each page, then download the app's JS bundles."""
    discovered = katana.discover(url, ctx)
    errors: list[str] = []
    pages: list[PageSnapshot] = []

    max_pages = max(1, ctx.settings.max_pages)
    with httpx.Client(
        follow_redirects=True,
        timeout=ctx.settings.request_timeout,
        headers={"User-Agent": ctx.settings.user_agent},
    ) as client:
        for page_url in select_urls(url, discovered, max_pages):
            if not ctx.gate.is_allowed(page_url):  # belt-and-suspenders re-check
                continue
            try:
                resp = client.get(page_url)
            except httpx.HTTPError as exc:
                errors.append(f"fetch failed for {page_url}: {exc}")
                continue
            pages.append(
                PageSnapshot(
                    url=str(resp.url),
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    html=resp.text,
                )
            )

        # Render JS-built pages (when Playwright is installed), then download the
        # app's own bundles (allowlisted hosts only — see js_bundle.py docstring).
        extra_scripts = _apply_rendering(pages, ctx)
        bundles = extract_bundles(pages, ctx, client=client, extra_urls=extra_scripts)

    # Endpoints = everything Katana discovered (even beyond the fetch cap);
    # pages = the subset we actually fetched above.
    endpoints = [Endpoint(url=d.url, method=d.method) for d in discovered]

    return Artifact(
        target_url=url,
        pages=pages,
        js_bundles=bundles,
        endpoints=endpoints,
        tech=fingerprint.detect(pages, bundles),
        errors=errors,
    )
