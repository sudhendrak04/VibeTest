"""JS bundle extraction tests with a fake HTTP client (no network)."""
from fake_http import FakeClient, FakeStreamResponse
from vibetest.acquisition import js_bundle
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.schemas.artifacts import PageSnapshot

BASE = "http://localhost:8000/"

HTML = """
<html><head>
<script src="/static/app.js"></script>
<script src="https://cdn.jsdelivr.net/npm/react.js"></script>
<script src="data:application/javascript;base64,AAAA"></script>
<script>inline script ignored</script>
<script src="/static/app.js"></script>
</head><body></body></html>
"""


def _ctx(gate=None):
    return ScanContext(settings=Settings(), gate=gate or ConsentGate(["localhost"]))


def test_extracts_own_bundles_only_and_captures_sourcemap():
    page = PageSnapshot(url=BASE, status_code=200, headers={}, html=HTML)
    client = FakeClient(
        {
            BASE + "static/app.js": FakeStreamResponse(
                200, {"content-type": "application/javascript"},
                b"const x = 1;\n//# sourceMappingURL=app.js.map",
            )
        }
    )
    bundles = js_bundle.extract_bundles([page], _ctx(), client=client)

    # Only the app's own bundle: CDN script blocked by consent gate, data: skipped,
    # duplicate deduped, inline script (no src) never collected.
    assert [b.url for b in bundles] == [BASE + "static/app.js"]
    assert client.calls == [BASE + "static/app.js"]
    assert bundles[0].source_map_url == BASE + "static/app.js.map"
    assert "const x = 1;" in bundles[0].content


def test_spa_fallback_html_bundle_is_skipped():
    page = PageSnapshot(url=BASE, status_code=200, headers={}, html='<script src="/shell.js"></script>')
    client = FakeClient(
        {BASE + "shell.js": FakeStreamResponse(200, {"content-type": "text/html"}, b"<!DOCTYPE html><html></html>")}
    )
    assert js_bundle.extract_bundles([page], _ctx(), client=client) == []


def test_malformed_html_never_raises():
    assert isinstance(js_bundle.script_srcs("<script src='broken <<>>"), list)


def test_cdn_bundle_never_requested_when_not_allowlisted():
    page = PageSnapshot(url=BASE, status_code=200, headers={}, html=HTML)
    client = FakeClient()
    js_bundle.extract_bundles([page], _ctx(), client=client)
    assert all("cdn.jsdelivr.net" not in url for url in client.calls)
