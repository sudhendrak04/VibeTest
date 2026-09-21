"""End-to-end pipeline test with an injected fake fetcher (no network)."""
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.orchestrator import run_scan
from vibetest.core.store import Store


def test_run_scan_end_to_end(mock_artifact):
    result = run_scan(
        "http://localhost:8000/",
        settings=Settings(enable_probes=False),  # hermetic: no probe client in tests
        gate=ConsentGate(["localhost"]),
        fetcher=lambda url, ctx: mock_artifact,
        no_llm=True,
    )
    assert result.findings, "expected the headers detector to fire on the mock artifact"
    assert {f.category for f in result.findings} == {"missing-security-header"}
    assert all(f.explanation for f in result.findings)  # template mode fills these
    # HSTS must NOT be flagged over plain HTTP
    assert all("strict-transport-security" not in f.title for f in result.findings)


def test_scan_persists_to_store(mock_artifact, tmp_path):
    store = Store(str(tmp_path / "test.db"))
    result = run_scan(
        "http://localhost:8000/",
        settings=Settings(enable_probes=False),  # hermetic: no probe client in tests
        gate=ConsentGate(["localhost"]),
        fetcher=lambda url, ctx: mock_artifact,
        store=store,
    )
    scans = store.list_scans()
    assert len(scans) == 1
    assert scans[0].scan_id == result.scan_id
