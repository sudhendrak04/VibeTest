"""Debug/dev build marker detector tests (pure — no network)."""
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors.debug_config import DebugConfigDetector
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.findings import Severity

BASE = "http://localhost:8000/"


def _ctx() -> ScanContext:
    return ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]))


def _artifact(html: str = "", bundles=None) -> Artifact:
    return Artifact(
        target_url=BASE,
        pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html=html)],
        js_bundles=list(bundles or []),
    )


def test_react_dev_build_detected():
    bundle = JSBundle(url=BASE + "static/app.js", content='require("react-dom.development");')
    findings = DebugConfigDetector().run(_artifact(bundles=[bundle]), _ctx())
    assert any(f.category == "debug-config" and f.severity is Severity.MEDIUM for f in findings)


def test_node_env_development_detected_in_bundle():
    bundle = JSBundle(url=BASE + "static/app.js", content='const cfg = { NODE_ENV: "development" };')
    findings = DebugConfigDetector().run(_artifact(bundles=[bundle]), _ctx())
    assert any("NODE_ENV" in f.title for f in findings)


def test_marker_detected_in_page_html():
    findings = DebugConfigDetector().run(
        _artifact(html='<script>var NODE_ENV = "development";</script>'), _ctx()
    )
    assert any("NODE_ENV" in f.title for f in findings)


def test_clean_assets_no_findings():
    bundle = JSBundle(url=BASE + "static/app.js", content="const add = (a, b) => a + b;")
    assert DebugConfigDetector().run(_artifact(html="<html></html>", bundles=[bundle]), _ctx()) == []
