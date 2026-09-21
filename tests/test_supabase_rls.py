"""Supabase RLS detector tests (fake HTTP client — no network)."""
import base64
import json

from fake_http import FakeClient, FakeStreamResponse
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors.supabase_rls import SupabaseRLSDetector
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.findings import Severity

APP = "http://localhost:8000/"
SUPA = "http://localhost:9000"
REST = SUPA + "/rest/v1/"


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


ANON_JWT = f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'role': 'anon'})}.sig"
SERVICE_JWT = f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'role': 'service_role'})}.sig"

SPEC = json.dumps({"swagger": "2.0", "paths": {"/users": {}, "/profiles": {}}}).encode()
ROW = json.dumps([{"id": 1, "email": "leaked@example.com", "phone": "+1-555-0100"}]).encode()


def _artifact(bundle_content: str) -> Artifact:
    return Artifact(
        target_url=APP,
        pages=[PageSnapshot(url=APP, status_code=200, headers={}, html="")],
        js_bundles=[JSBundle(url=APP + "static/app.js", content=bundle_content)],
    )


def _ctx(client) -> ScanContext:
    return ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]), allow_probes=True, http=client)


def test_exposed_table_is_critical_and_redacted():
    content = f'const SUPABASE_URL = "{SUPA}"; const KEY = "{ANON_JWT}";'
    client = FakeClient(
        {
            REST: FakeStreamResponse(200, {"content-type": "application/json"}, SPEC),
            REST + "users?select=*&limit=1": FakeStreamResponse(200, {"content-type": "application/json"}, ROW),
            REST + "profiles?select=*&limit=1": FakeStreamResponse(200, {"content-type": "application/json"}, b"[]"),
        }
    )
    findings = SupabaseRLSDetector().run(_artifact(content), _ctx(client))

    assert len(findings) == 1  # users exposed; profiles ([]) not reported
    f = findings[0]
    assert f.severity is Severity.CRITICAL
    assert "users" in f.title
    snippet = f.evidence[0].snippet
    assert "1 row(s)" in snippet
    assert "email" in snippet
    assert "leaked@example.com" not in snippet  # row VALUES never appear in evidence
    assert client.seen_headers[0].get("apikey") == ANON_JWT  # probed with the public key


def test_protected_root_makes_no_table_probes():
    client = FakeClient({REST: FakeStreamResponse(401, {"content-type": "application/json"}, b'{"message":"Invalid API key"}')})
    findings = SupabaseRLSDetector().run(_artifact(f'const SUPABASE_URL = "{SUPA}"; const K = "{ANON_JWT}";'), _ctx(client))
    assert findings == []
    assert client.calls == [REST]


def test_non_allowlisted_supabase_host_is_never_probed():
    content = f'const SUPABASE_URL = "https://abcdefghijklm.supabase.co"; const K = "{ANON_JWT}";'
    client = FakeClient()
    findings = SupabaseRLSDetector().run(_artifact(content), _ctx(client))
    assert findings == []
    assert client.calls == []  # consent gate blocked before any request


def test_service_role_key_alone_probes_nothing():
    content = f'const SUPABASE_URL = "{SUPA}"; const K = "{SERVICE_JWT}";'
    client = FakeClient()
    findings = SupabaseRLSDetector().run(_artifact(content), _ctx(client))
    assert findings == []
    assert client.calls == []  # RLS test requires the PUBLIC key; service_role would bypass and prove nothing


def test_no_supabase_markers_makes_no_requests():
    client = FakeClient()
    findings = SupabaseRLSDetector().run(_artifact("const x = 1;"), _ctx(client))
    assert findings == []
    assert client.calls == []


def test_publishable_key_supported():
    content = f'const SUPABASE_URL = "{SUPA}"; const K = "sb_publishable_demo1234567890";'
    client = FakeClient(
        {
            REST: FakeStreamResponse(200, {"content-type": "application/json"}, SPEC),
            REST + "users?select=*&limit=1": FakeStreamResponse(200, {"content-type": "application/json"}, ROW),
            REST + "profiles?select=*&limit=1": FakeStreamResponse(200, {"content-type": "application/json"}, b"[]"),
        }
    )
    findings = SupabaseRLSDetector().run(_artifact(content), _ctx(client))
    assert len(findings) == 1
    assert client.seen_headers[0].get("apikey") == "sb_publishable_demo1234567890"
