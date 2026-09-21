"""Playwright rendering tests — no browser, no network."""
from fake_http import FakeClient, FakeStreamResponse
from vibetest.acquisition import crawler, js_bundle, render
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.schemas.artifacts import PageSnapshot

BASE = "http://localhost:8000/"


def _page(html: str) -> PageSnapshot:
    return PageSnapshot(url=BASE, status_code=200, headers={}, html=html)


def _ctx(**settings_kwargs) -> ScanContext:
    return ScanContext(settings=Settings(**settings_kwargs), gate=ConsentGate(["localhost"]))


def test_looks_like_spa_for_sparse_shell():
    html = '<html><body><div id="root"></div><script>const x = 1;</script></body></html>'
    assert render.looks_like_spa(_page(html)) is True


def test_looks_like_spa_false_for_content_rich_page():
    paragraphs = "".join(f"<p>paragraph {i} with plenty of text here</p>" for i in range(20))
    html = f"<html><body>{paragraphs}<script>1</script></body></html>"
    assert render.looks_like_spa(_page(html)) is False


def test_looks_like_spa_false_without_scripts():
    assert render.looks_like_spa(_page("<html><body><h1>plain</h1></body></html>")) is False


def test_should_block_policies():
    gate = ConsentGate(["localhost"])
    assert render.should_block(f"{BASE}logo.png", "image", gate) is True  # heavy media skipped
    assert render.should_block(f"{BASE}static/app.js", "script", gate) is False
    assert render.should_block("https://cdn.other.test/lib.js", "script", gate) is True


def test_render_pages_returns_empty_for_no_urls():
    assert render.render_pages([], gate=ConsentGate(["localhost"]), settings=Settings()) == {}


def test_apply_rendering_replaces_html_and_collects_scripts(monkeypatch):
    page = _page('<div id="root"></div><script>x</script>')
    monkeypatch.setattr(crawler.render, "looks_like_spa", lambda p: True)
    monkeypatch.setattr(
        crawler.render,
        "render_pages",
        lambda urls, gate, settings: {
            urls[0]: crawler.render.RenderedPage(
                html="<html>rendered</html>", script_urls=[f"{BASE}static/late.js"]
            )
        },
    )
    extra = crawler._apply_rendering([page], _ctx())
    assert page.html == "<html>rendered</html>"
    assert extra == [f"{BASE}static/late.js"]


def test_apply_rendering_skipped_when_disabled(monkeypatch):
    calls: list = []
    monkeypatch.setattr(crawler.render, "render_pages", lambda *a, **k: calls.append(1) or {})
    page = _page('<div id="root"></div><script>x</script>')
    assert crawler._apply_rendering([page], _ctx(render_spa=False)) == []
    assert calls == []


def test_extract_bundles_includes_extra_urls():
    page = _page("<html></html>")
    client = FakeClient(
        {
            f"{BASE}static/late.js": FakeStreamResponse(
                200, {"content-type": "application/javascript"}, b"const x = 1;"
            )
        }
    )
    bundles = js_bundle.extract_bundles(
        [page], _ctx(), client=client, extra_urls=[f"{BASE}static/late.js"]
    )
    assert [b.url for b in bundles] == [f"{BASE}static/late.js"]


def test_extract_bundles_blocks_non_allowlisted_extra_urls():
    page = _page("<html></html>")
    client = FakeClient()
    bundles = js_bundle.extract_bundles(
        [page], _ctx(), client=client, extra_urls=["https://cdn.other.test/lib.js"]
    )
    assert bundles == []
    assert client.calls == []
