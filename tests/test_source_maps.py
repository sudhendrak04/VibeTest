"""Source-map detector tests (fake HTTP client — no network)."""
import json

from fake_http import FakeClient, FakeStreamResponse
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors.source_maps import SourceMapsDetector
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.findings import Severity

BASE = "http://localhost:8000/"
BUNDLE_URL = BASE + "static/app.js"
MAP_URL = BUNDLE_URL + ".map"

MAP_BODY = json.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sources": ["../src/App.tsx", "../src/api.ts"],
        "mappings": "AAAA,IAAM,GAAG",
    }
).encode()


def _artifact(bundle: JSBundle) -> Artifact:
    return Artifact(
        target_url=BASE,
        pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")],
        js_bundles=[bundle],
    )


def _ctx(client) -> ScanContext:
    return ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]), allow_probes=True, http=client)


def test_referenced_source_map_is_reported():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url=MAP_URL)
    client = FakeClient({MAP_URL: FakeStreamResponse(200, {"content-type": "application/json"}, MAP_BODY)})
    findings = SourceMapsDetector().run(_artifact(bundle), _ctx(client))

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "source-map-exposed"
    assert f.severity is Severity.LOW
    assert "2 source file(s)" in f.evidence[0].snippet
    assert client.calls == [MAP_URL]


def test_map_without_comment_is_probed_by_convention():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url=None)
    client = FakeClient({MAP_URL: FakeStreamResponse(200, {"content-type": "application/json"}, MAP_BODY)})
    findings = SourceMapsDetector().run(_artifact(bundle), _ctx(client))

    assert len(findings) == 1
    assert client.calls == [MAP_URL]


def test_spa_fallback_map_is_not_a_finding():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url=MAP_URL)
    client = FakeClient(
        {MAP_URL: FakeStreamResponse(200, {"content-type": "text/html"}, b"<!DOCTYPE html><html></html>")}
    )
    assert SourceMapsDetector().run(_artifact(bundle), _ctx(client)) == []


def test_missing_map_is_not_a_finding():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url=MAP_URL)
    assert SourceMapsDetector().run(_artifact(bundle), _ctx(FakeClient())) == []


def test_malformed_json_is_not_a_finding():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url=MAP_URL)
    client = FakeClient({MAP_URL: FakeStreamResponse(200, {"content-type": "application/json"}, b'{"hello": 1}')})
    assert SourceMapsDetector().run(_artifact(bundle), _ctx(client)) == []


def test_non_allowlisted_map_host_makes_no_requests():
    bundle = JSBundle(url=BUNDLE_URL, content="x", source_map_url="https://cdn.other-host.test/app.js.map")
    client = FakeClient()
    ctx = ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]), allow_probes=True, http=client)
    assert SourceMapsDetector().run(_artifact(bundle), ctx) == []
    assert client.calls == []
