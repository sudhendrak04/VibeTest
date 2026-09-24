"""Dashboard tests (FastAPI TestClient — no network, no live server)."""
import threading
import time
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from vibetest.core.store import Store
from vibetest.schemas.artifacts import Artifact, JSBundle, PageSnapshot, TechFingerprint
from vibetest.schemas.findings import Evidence, Finding, Severity
from vibetest.schemas.scan import ScanResult
from vibetest.web.app import create_app

BASE = "http://localhost:8000/"


def _seed(tmp_path) -> str:
    db = str(tmp_path / "web.db")
    store = Store(db)
    artifact = Artifact(
        target_url=BASE,
        pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")],
        tech=TechFingerprint(framework="next.js", hosting="vercel", backend_services=["supabase"]),
    )
    finding = Finding(
        detector_id="headers",
        category="missing-security-header",
        cwe_id="CWE-693",
        owasp_2025="A02:2025",
        severity=Severity.MEDIUM,
        title="Missing security header: content-security-policy",
        evidence=[Evidence(url=BASE, detail="response missing `content-security-policy`")],
        remediation_hint="Add a CSP header.",
        explanation="What this means: plain-English explanation.",
    )
    store.save_scan(
        ScanResult(
            scan_id="abc123",
            target_url=BASE,
            started_at=datetime.now(timezone.utc),
            artifact=artifact,
            findings=[finding],
        )
    )
    return db


def test_index_lists_scans(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    resp = client.get("/")
    assert resp.status_code == 200
    assert BASE in resp.text
    assert "medium" in resp.text.lower()


def test_scan_detail_shows_finding_and_tech(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    resp = client.get("/scan/abc123")
    assert resp.status_code == 200
    assert "Missing security header: content-security-policy" in resp.text
    assert "next.js" in resp.text
    assert "supabase" in resp.text


def test_scan_report_route_renders_full_report(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    resp = client.get("/scan/abc123/report")
    assert resp.status_code == 200
    assert "VibeTest security report" in resp.text


def test_api_scans_lists_and_details(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    listing = client.get("/api/scans").json()
    assert listing[0]["scan_id"] == "abc123"
    detail = client.get("/api/scans/abc123").json()
    assert detail["tech"][0] == "next.js"
    assert detail["findings"][0]["severity"] == "medium"


def test_index_shows_overview_stats(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    resp = client.get("/")
    assert "Total findings" in resp.text
    assert "Critical" in resp.text
    assert "Scan a website" in resp.text


def test_unknown_scan_returns_404(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    assert client.get("/scan/nope").status_code == 404
    assert client.get("/api/scans/nope").status_code == 404


# ------------------------------------------------------- scan-from-dashboard

def _ok_runner(url, settings, gate, store):
    artifact = Artifact(
        target_url=url,
        pages=[PageSnapshot(url=url, status_code=200, headers={}, html="")],
    )
    result = ScanResult(
        scan_id="scan-happy",
        target_url=url,
        started_at=datetime.now(timezone.utc),
        artifact=artifact,
        findings=[],
    )
    store.save_scan(result)
    return result


def _repo_result(ref: str, store) -> ScanResult:
    artifact = Artifact(
        target_url=f"https://github.com/{ref}",
        pages=[],
        js_bundles=[JSBundle(url="src/app.js", content="const x = 1;")],
    )
    result = ScanResult(
        scan_id="scan-repo",
        target_url=artifact.target_url,
        started_at=datetime.now(timezone.utc),
        artifact=artifact,
        findings=[],
    )
    store.save_scan(result)
    return result


def _poll_job(client, job_id: str, timeout: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = client.get(f"/api/scan/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.02)
    raise AssertionError("scan job did not finish in time")


def test_scan_api_happy_path(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    resp = client.post("/api/scan", json={"url": "http://localhost:8000/", "authorized": True})
    assert resp.status_code == 202
    assert resp.json()["mode"] == "url"
    job = _poll_job(client, resp.json()["job_id"])
    assert job["status"] == "done"
    assert job["scan_id"] == "scan-happy"
    assert client.get("/scan/scan-happy").status_code == 200


def test_scan_api_requires_authorization_confirmation(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    resp = client.post("/api/scan", json={"url": "http://localhost:8000/"})
    assert resp.status_code == 403
    assert "checkbox" in resp.json()["detail"].lower()


def test_scan_api_confirmed_host_gets_run_scoped_gate(tmp_path):
    captured = {}

    def capturing_runner(url, settings, gate, store):
        captured["gate"] = gate
        return _ok_runner(url, settings, gate, store)

    client = TestClient(create_app(_seed(tmp_path), scan_runner=capturing_runner))
    resp = client.post(
        "/api/scan", json={"url": "https://friend-site.example/", "authorized": True}
    )
    assert resp.status_code == 202
    job = _poll_job(client, resp.json()["job_id"])
    assert job["status"] == "done"
    # the confirmed host was allowlisted for this run only, not globally
    assert captured["gate"].is_allowed("https://friend-site.example/some/page")
    assert captured["gate"].is_allowed("http://localhost:8000/")  # config entries kept


def test_scan_api_rejects_bad_url(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    resp = client.post("/api/scan", json={"url": "not-a-url", "authorized": True})
    assert resp.status_code == 400


def test_scan_api_auto_detects_github_reference(tmp_path):
    calls = []

    def fake_repo(ref, settings, store):
        calls.append(ref)
        return _repo_result(ref, store)

    client = TestClient(create_app(_seed(tmp_path), repo_runner=fake_repo))
    resp = client.post("/api/scan", json={"url": "github.com/o/r", "authorized": True})
    assert resp.status_code == 202
    assert resp.json()["mode"] == "repo"
    job = _poll_job(client, resp.json()["job_id"])
    assert job["status"] == "done"
    assert calls == ["o/r"]
    assert client.get("/scan/scan-repo").status_code == 200


def test_scan_api_accepts_plain_owner_repo(tmp_path):
    calls = []

    def fake_repo(ref, settings, store):
        calls.append(ref)
        return _repo_result(ref, store)

    client = TestClient(create_app(_seed(tmp_path), repo_runner=fake_repo))
    resp = client.post("/api/scan", json={"url": "o/r", "authorized": True})
    assert resp.status_code == 202
    _poll_job(client, resp.json()["job_id"])
    assert calls == ["o/r"]


def test_scan_api_rejects_unknown_reference(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    resp = client.post("/api/scan", json={"url": "gitlab.com/o/r", "authorized": True})
    assert resp.status_code == 400


def test_scan_api_failure_is_reported(tmp_path):
    def boom(url, settings, gate, store):
        raise RuntimeError("scan exploded")

    client = TestClient(create_app(_seed(tmp_path), scan_runner=boom))
    resp = client.post("/api/scan", json={"url": "http://localhost:8000/", "authorized": True})
    assert resp.status_code == 202
    job = _poll_job(client, resp.json()["job_id"])
    assert job["status"] == "failed"
    assert "exploded" in job["error"]


def test_scan_api_single_flight(tmp_path):
    release = threading.Event()

    def slow_runner(url, settings, gate, store):
        release.wait(timeout=5)
        return _ok_runner(url, settings, gate, store)

    client = TestClient(create_app(_seed(tmp_path), scan_runner=slow_runner))
    first = client.post("/api/scan", json={"url": "http://localhost:8000/", "authorized": True})
    assert first.status_code == 202
    second = client.post("/api/scan", json={"url": "http://localhost:8000/", "authorized": True})
    assert second.status_code == 409
    release.set()
    job = _poll_job(client, first.json()["job_id"])
    assert job["status"] == "done"


def test_scan_detail_shows_kind_badge(tmp_path):
    db = _seed(tmp_path)  # website scan (has fetched pages)
    client = TestClient(create_app(db))
    assert "Website" in client.get("/scan/abc123").text

    store = Store(db)
    _repo_result("o/r", store)  # repo-like scan (no pages, relative-path bundles)
    assert "GitHub repository" in client.get("/scan/scan-repo").text

    # Edge case: a repo with no recognized text files (e.g. octocat/Hello-World,
    # whose README has no extension) has no bundles at all — github.com target
    # must still classify it as a repository.
    empty_repo = ScanResult(
        scan_id="scan-repo-empty",
        target_url="https://github.com/o/empty",
        started_at=datetime.now(timezone.utc),
        artifact=Artifact(target_url="https://github.com/o/empty", pages=[], js_bundles=[]),
        findings=[],
    )
    store.save_scan(empty_repo)
    assert "GitHub repository" in client.get("/scan/scan-repo-empty").text


# ------------------------------------------------------------- PDF download

def test_scan_report_pdf_downloads(tmp_path):
    captured = {}

    def fake_pdf(html: str) -> bytes:
        captured["html"] = html
        return b"%PDF-1.4 fake"

    client = TestClient(create_app(_seed(tmp_path), pdf_renderer=fake_pdf))
    resp = client.get("/scan/abc123/report.pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    disposition = resp.headers["content-disposition"]
    assert "attachment" in disposition
    assert disposition.endswith('.pdf"')
    assert "vibetest-localhost-" in disposition
    assert resp.content.startswith(b"%PDF")
    assert "Missing security header: content-security-policy" in captured["html"]


def test_scan_report_pdf_unknown_scan_returns_404(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), pdf_renderer=lambda html: b"%PDF"))
    assert client.get("/scan/nope/report.pdf").status_code == 404


def test_scan_report_pdf_failure_returns_503(tmp_path):
    def boom(html: str) -> bytes:
        raise RuntimeError("playwright not installed")

    client = TestClient(create_app(_seed(tmp_path), pdf_renderer=boom))
    resp = client.get("/scan/abc123/report.pdf")
    assert resp.status_code == 503
    assert "playwright" in resp.json()["detail"].lower()


def test_scan_detail_has_pdf_button(tmp_path):
    client = TestClient(create_app(_seed(tmp_path)))
    body = client.get("/scan/abc123").text
    assert "Download PDF" in body
    assert "/scan/abc123/report.pdf" in body
