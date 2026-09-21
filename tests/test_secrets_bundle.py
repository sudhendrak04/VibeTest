"""Secrets-in-bundle detector tests (pure — no network, no client needed)."""
import base64
import json

from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors.secrets_bundle import SecretsBundleDetector
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot
from vibetest.schemas.findings import Severity

BASE = "http://localhost:8000/"


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


def _jwt(role: str) -> str:
    return f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'role': role})}.sig"


SERVICE_JWT = _jwt("service_role")
ANON_JWT = _jwt("anon")


def _run(content: str):
    artifact = Artifact(
        target_url=BASE,
        pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")],
        js_bundles=[JSBundle(url=BASE + "static/app.js", content=content)],
    )
    ctx = ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]))
    return SecretsBundleDetector().run(artifact, ctx)


def test_service_role_jwt_is_critical_and_masked():
    findings = _run(f'const SUPABASE_KEY = "{SERVICE_JWT}";\n')
    matches = [f for f in findings if f.title == "Supabase service_role key in client bundle"]
    assert matches, "service_role JWT must be detected"
    f = matches[0]
    assert f.severity is Severity.CRITICAL
    assert f.confidence == 0.95
    for ev in f.evidence:
        assert SERVICE_JWT not in ev.snippet  # never republish the usable secret
        assert "eyJhbG" in ev.snippet  # masked form keeps the first chars


def test_anon_jwt_is_not_a_finding():
    """The anon key is public BY DESIGN — flagging it would be a false positive."""
    assert _run(f'const SUPABASE_ANON_KEY = "{ANON_JWT}";\n') == []


def test_sb_secret_key_detected_and_masked():
    secret = "sb_secret_demo0123456789abcdef"
    findings = _run(f'const S = "{secret}";\n')
    assert findings and findings[0].severity is Severity.CRITICAL
    snippet = findings[0].evidence[0].snippet
    assert secret not in snippet
    assert "sb_sec***" in snippet


def test_aws_key_detected_and_masked():
    key = "AKIAABCDEFGHIJKLMNOP"
    findings = _run(f'awsAccessKeyId = "{key}"\n')
    assert findings
    assert key not in findings[0].evidence[0].snippet
    assert "AKIAAB***" in findings[0].evidence[0].snippet


def test_private_key_block_detected():
    findings = _run("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n")
    assert any(f.severity is Severity.CRITICAL for f in findings)


def test_clean_bundle_has_no_findings():
    assert _run("const add = (a, b) => a + b;\nconsole.log(add(1, 2));\n") == []


def test_google_api_key_is_high_not_critical():
    key = "AIzaSyA1234567890abcdefghijklmnopqrstuv"  # AIza + exactly 35 chars (39 total)
    findings = _run(f'const g = "{key}";\n')
    matches = [f for f in findings if f.title == "Google API key in client bundle"]
    assert matches and matches[0].severity is Severity.HIGH
    assert key not in matches[0].evidence[0].snippet  # masked
