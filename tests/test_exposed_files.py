"""Exposed-files detector tests with a fake HTTP client (no network)."""
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.core.orchestrator import run_scan
from vibetest.detectors.exposed_files import ExposedFilesDetector
from vibetest.schemas.artifacts import Artifact, PageSnapshot
from vibetest.schemas.findings import Severity
from fake_http import FakeClient, FakeStreamResponse

BASE = "http://localhost:8000/"


def _artifact(url: str = BASE) -> Artifact:
    return Artifact(
        target_url=url,
        pages=[PageSnapshot(url=url, status_code=200, headers={}, html="<html></html>")],
    )


def _ctx(client=None) -> ScanContext:
    return ScanContext(
        settings=Settings(),
        gate=ConsentGate(["localhost"]),
        allow_probes=True,
        http=client,
    )


def test_env_exposed_is_critical_and_redacted():
    body = b"SUPABASE_SERVICE_KEY=demo_secret_value_123\nDEBUG=true\n"
    client = FakeClient({BASE + ".env": FakeStreamResponse(200, {"content-type": "text/plain"}, body)})
    findings = ExposedFilesDetector().run(_artifact(), _ctx(client))
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "exposed-sensitive-file"
    assert f.severity is Severity.CRITICAL
    assert f.cwe_id == "CWE-538"
    snippet = f.evidence[0].snippet
    assert "demo_secret_value_123" not in snippet  # value redacted
    assert "SUPABASE_SERVICE_KEY=***" in snippet


def test_spa_fallback_html_200_is_not_a_finding():
    """Vercel/Netlify answer 200 + app shell for unknown paths — must NOT count as exposure."""
    body = b"<!DOCTYPE html><html><head><title>app</title></head></html>"
    client = FakeClient(
        {BASE + ".env": FakeStreamResponse(200, {"content-type": "text/html; charset=utf-8"}, body)}
    )
    assert ExposedFilesDetector().run(_artifact(), _ctx(client)) == []


def test_git_head_detected():
    client = FakeClient(
        {BASE + ".git/HEAD": FakeStreamResponse(200, {"content-type": "application/octet-stream"}, b"ref: refs/heads/main\n")}
    )
    findings = ExposedFilesDetector().run(_artifact(), _ctx(client))
    assert findings and findings[0].title == "Exposed sensitive file: /.git/HEAD"


def test_404_everywhere_produces_no_findings():
    assert ExposedFilesDetector().run(_artifact(), _ctx(FakeClient())) == []


def test_probes_respect_consent_gate():
    # Artifact host is NOT on the allowlist → detector must not make any request at all.
    client = FakeClient()
    ctx = ScanContext(settings=Settings(), gate=ConsentGate(["some-other-host.test"]), allow_probes=True, http=client)
    assert ExposedFilesDetector().run(_artifact(), ctx) == []
    assert client.calls == []


def test_pipeline_includes_exposed_files_with_fake_client(mock_artifact):
    client = FakeClient({BASE + ".env": FakeStreamResponse(200, {"content-type": "text/plain"}, b"API_KEY=abc123\n")})
    result = run_scan(
        BASE,
        settings=Settings(),
        gate=ConsentGate(["localhost"]),
        fetcher=lambda url, ctx: mock_artifact,
        http_client=client,
        no_llm=True,
    )
    assert any(f.detector_id == "exposed_files" for f in result.findings)
    assert any(f.detector_id == "headers" for f in result.findings)
