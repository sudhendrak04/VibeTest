"""Firebase rules detector tests (fake HTTP client — no network)."""
from fake_http import FakeClient, FakeStreamResponse
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors.firebase_rules import FirebaseRulesDetector
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.findings import Severity

BASE = "http://localhost:8000/"
RTDB = "https://demo-project-default-rtdb.firebaseio.com"
RTDB_JSON = RTDB + "/.json"


def _artifact(content: str) -> Artifact:
    return Artifact(
        target_url=BASE,
        pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")],
        js_bundles=[JSBundle(url=BASE + "static/app.js", content=content)],
    )


def _ctx(client, allowed=("localhost", "demo-project-default-rtdb.firebaseio.com")) -> ScanContext:
    return ScanContext(
        settings=Settings(),
        gate=ConsentGate(list(allowed)),
        allow_probes=True,
        http=client,
    )


def test_open_rtdb_with_data_is_critical_and_redacted():
    content = f'const firebaseConfig = {{ databaseURL: "{RTDB}" }};'
    client = FakeClient(
        {
            RTDB_JSON: FakeStreamResponse(
                200,
                {"content-type": "application/json"},
                b'{"users": {"u1": {"email": "leaked@example.com"}}}',
            )
        }
    )
    findings = FirebaseRulesDetector().run(_artifact(content), _ctx(client))

    assert len(findings) == 1
    f = findings[0]
    assert f.category == "firebase-rules-open"
    assert f.severity is Severity.CRITICAL
    assert "users" in f.evidence[0].snippet
    assert "leaked@example.com" not in f.evidence[0].snippet  # values never shown
    assert client.calls == [RTDB_JSON]


def test_empty_database_public_read_is_medium():
    content = f'const databaseURL = "{RTDB}";'
    client = FakeClient({RTDB_JSON: FakeStreamResponse(200, {"content-type": "application/json"}, b"null")})
    findings = FirebaseRulesDetector().run(_artifact(content), _ctx(client))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "currently empty" in findings[0].title


def test_permission_denied_is_not_a_finding():
    content = f'const databaseURL = "{RTDB}";'
    client = FakeClient(
        {
            RTDB_JSON: FakeStreamResponse(
                401, {"content-type": "application/json"}, b'{"error":"Permission denied"}'
            )
        }
    )
    assert FirebaseRulesDetector().run(_artifact(content), _ctx(client)) == []


def test_html_decoy_rejected():
    content = f'const databaseURL = "{RTDB}";'
    client = FakeClient(
        {RTDB_JSON: FakeStreamResponse(200, {"content-type": "text/html"}, b"<!DOCTYPE html><html></html>")}
    )
    assert FirebaseRulesDetector().run(_artifact(content), _ctx(client)) == []


def test_bare_host_reference_and_regional_url_detected():
    regional = "https://proj-default-rtdb.europe-west1.firebasedatabase.app"
    content = f'const u1 = "https://proj.firebaseio.com"; const u2 = "{regional}";'
    client = FakeClient(
        {
            "https://proj.firebaseio.com/.json": FakeStreamResponse(
                200, {"content-type": "application/json"}, b"null"
            ),
            regional + "/.json": FakeStreamResponse(
                200, {"content-type": "application/json"}, b"null"
            ),
        }
    )
    ctx = _ctx(
        client,
        allowed=("localhost", "proj.firebaseio.com", "proj-default-rtdb.europe-west1.firebasedatabase.app"),
    )
    findings = FirebaseRulesDetector().run(_artifact(content), ctx)
    assert len(findings) == 2
    assert all(f.severity is Severity.MEDIUM for f in findings)


def test_non_allowlisted_host_makes_no_requests():
    content = f'const databaseURL = "{RTDB}";'
    client = FakeClient()
    ctx = ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]), allow_probes=True, http=client)
    assert FirebaseRulesDetector().run(_artifact(content), ctx) == []
    assert client.calls == []


def test_no_firebase_markers_no_requests():
    client = FakeClient()
    assert FirebaseRulesDetector().run(_artifact("const x = 1;"), _ctx(client)) == []
    assert client.calls == []
