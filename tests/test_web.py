"""Dashboard tests (FastAPI TestClient — no network, no live server)."""
import threading
import time
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from vibetest.core.store import Store
from vibetest.schemas.artifacts import Artifact, PageSnapshot, TechFingerprint
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
    resp = client.post("/api/scan", json={"url": "http://localhost:8000/"})
    assert resp.status_code == 202
    job = _poll_job(client, resp.json()["job_id"])
    assert job["status"] == "done"
    assert job["scan_id"] == "scan-happy"
    assert client.get("/scan/scan-happy").status_code == 200


def test_scan_api_refuses_non_allowlisted(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    resp = client.post("/api/scan", json={"url": "https://evil.example.com/"})
    assert resp.status_code == 403
    assert "allowlist" in resp.json()["detail"].lower()


def test_scan_api_rejects_bad_url(tmp_path):
    client = TestClient(create_app(_seed(tmp_path), scan_runner=_ok_runner))
    assert client.post("/api/scan", json={"url": "not-a-url"}).status_code == 400


def test_scan_api_failure_is_reported(tmp_path):
    def boom(url, settings, gate, store):
        raise RuntimeError("scan exploded")

    client = TestClient(create_app(_seed(tmp_path), scan_runner=boom))
    resp = client.post("/api/scan", json={"url": "http://localhost:8000/"})
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
    first = client.post("/api/scan", json={"url": "http://localhost:8000/"})
    assert first.status_code == 202
    second = client.post("/api/scan", json={"url": "http://localhost:8000/"})
    assert second.status_code == 409
    release.set()
    job = _poll_job(client, first.json()["job_id"])
    assert job["status"] == "done"
