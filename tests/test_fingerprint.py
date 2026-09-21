"""Technology fingerprinter tests (pure — no network)."""
from datetime import datetime, timezone

from vibetest.acquisition import fingerprint
from vibetest.reporting.html_report import render_report
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.scan import ScanResult

BASE = "http://localhost:8000/"


def _page(headers: dict | None = None, html: str = "") -> PageSnapshot:
    return PageSnapshot(url=BASE, status_code=200, headers=headers or {}, html=html)


def _bundle(content: str) -> JSBundle:
    return JSBundle(url=BASE + "static/app.js", content=content)


def test_vercel_nextjs_supabase_detected():
    pages = [_page({"x-vercel-id": "abc123"}, html="<script>window.__NEXT_DATA__={}</script>")]
    tech = fingerprint.detect(pages, [_bundle('const url = "https://demo.supabase.co";')])
    assert tech.framework == "next.js"
    assert tech.hosting == "vercel"
    assert tech.backend_services == ["supabase"]


def test_netlify_hosting_and_express_framework():
    tech = fingerprint.detect([_page({"x-nf-request-id": "1", "x-powered-by": "Express"})], [])
    assert tech.hosting == "netlify"
    assert tech.framework == "express"
    assert tech.backend_services == []


def test_services_from_bundle_are_sorted_and_deduplicated():
    pages = [_page(html="<script src='/static/app.js'></script>")]
    bundles = [
        _bundle('firebase.initializeApp({databaseURL: "https://demo.firebaseio.com"});'),
        _bundle("Sentry.init({ dsn: 'https://demo@o0.ingest.sentry.io/0' });"),
        _bundle('const again = "https://demo.firebaseapp.com";'),
    ]
    tech = fingerprint.detect(pages, bundles)
    assert tech.backend_services == ["firebase", "sentry"]


def test_no_signals_returns_empty_fingerprint():
    tech = fingerprint.detect([_page(html="<html><body>hello</body></html>")], [])
    assert tech.framework is None
    assert tech.hosting is None
    assert tech.backend_services == []


def test_sveltekit_and_github_pages():
    pages = [_page({"server": "GitHub.com"}, html='<div data-sveltekit-preload-data="hover"></div>')]
    tech = fingerprint.detect(pages, [])
    assert tech.framework == "sveltekit"
    assert tech.hosting == "github-pages"


def test_report_shows_detected_technology():
    artifact = Artifact(
        target_url=BASE,
        pages=[_page({"x-vercel-id": "abc"}, html="<script>window.__NEXT_DATA__={}</script>")],
        js_bundles=[_bundle('const u = "https://demo.supabase.co";')],
        tech=fingerprint.detect(
            [_page({"x-vercel-id": "abc"}, html="<script>window.__NEXT_DATA__={}</script>")],
            [_bundle('const u = "https://demo.supabase.co";')],
        ),
    )
    result = ScanResult(
        scan_id="test",
        target_url=BASE,
        started_at=datetime.now(timezone.utc),
        artifact=artifact,
        findings=[],
    )
    html = render_report(result)
    assert "Detected technology: next.js · vercel · supabase" in html
