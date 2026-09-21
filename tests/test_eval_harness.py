"""Evaluation harness metric tests (pure — no network, no fixtures)."""
from datetime import datetime, timezone

from eval import harness
from eval.harness import evaluate
from vibetest.schemas.artifacts import Artifact, PageSnapshot
from vibetest.schemas.findings import Finding, Severity
from vibetest.schemas.scan import ScanResult

BASE = "http://localhost:8000/"


def _result(categories: list[str], titles: list[str] | None = None) -> ScanResult:
    findings = [
        Finding(detector_id="test", category=category, severity=Severity.LOW, title=title)
        for category, title in zip(categories, titles or categories)
    ]
    return ScanResult(
        scan_id="x",
        target_url=BASE,
        started_at=datetime.now(timezone.utc),
        artifact=Artifact(
            target_url=BASE,
            pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")],
        ),
        findings=findings,
    )


def test_perfect_match_scores_one():
    report = evaluate(_result(["a", "b"]), {"name": "t", "expect": ["a", "b"]})
    assert report["precision"] == 1.0
    assert report["recall"] == 1.0
    assert report["violations"] == []


def test_missing_category_lowers_recall():
    report = evaluate(_result(["a"]), {"name": "t", "expect": ["a", "b"]})
    assert report["recall"] == 0.5
    assert report["fn"] == ["b"]


def test_unexpected_category_lowers_precision():
    report = evaluate(_result(["a", "x"]), {"name": "t", "expect": ["a"]})
    assert report["precision"] == 0.5
    assert report["fp"] == ["x"]


def test_forbidden_category_is_a_violation():
    report = evaluate(
        _result(["a", "secret-in-bundle"]),
        {"name": "t", "expect": ["a"], "forbid_categories": ["secret-in-bundle"]},
    )
    assert report["violations"] == ["forbidden category present: secret-in-bundle"]


def test_forbidden_title_substring_is_a_violation():
    result = _result(["a"], titles=["Supabase table readable: profiles"])
    report = evaluate(result, {"name": "t", "expect": ["a"], "forbid_title_contains": ["profiles"]})
    assert len(report["violations"]) == 1
    assert "profiles" in report["violations"][0]


# --------------------------------------------------------- target dispatch

def _fake_result(target_url: str) -> ScanResult:
    return ScanResult(
        scan_id="x",
        target_url=target_url,
        started_at=datetime.now(timezone.utc),
        artifact=Artifact(
            target_url=target_url,
            pages=[PageSnapshot(url=target_url, status_code=200, headers={}, html="")],
        ),
        findings=[],
    )


def test_run_evaluation_routes_repo_mode_and_skips_render_targets(monkeypatch):
    calls: list[tuple] = []

    def fake_run_scan(url, **kwargs):
        calls.append(("url", url))
        return _fake_result(url)

    def fake_run_repo(ref, **kwargs):
        calls.append(("repo", ref, kwargs.get("github_base")))
        return _fake_result(ref)

    monkeypatch.setattr(
        harness,
        "load_targets",
        lambda: [
            {"name": "u", "url": "http://127.0.0.1:9999/", "expect": []},
            {
                "name": "r",
                "mode": "repo",
                "repo": "o/r",
                "github_base": "http://127.0.0.1:8130",
                "ready_url": "http://127.0.0.1:8130/",
                "expect": [],
            },
            {"name": "spa", "url": "http://127.0.0.1:9998/", "requires_render": True, "expect": []},
        ],
    )
    monkeypatch.setattr(harness, "Store", lambda path: None)
    monkeypatch.setattr(harness, "_ensure_fixture", lambda spec: None)
    monkeypatch.setattr(harness, "run_scan", fake_run_scan)
    monkeypatch.setattr(harness, "run_repo_scan", fake_run_repo)
    monkeypatch.setattr(harness.render, "is_available", lambda: False)

    report = harness.run_evaluation()

    assert [row["name"] for row in report["targets"]] == ["u", "r"]  # SPA skipped
    assert calls == [
        ("url", "http://127.0.0.1:9999/"),
        ("repo", "o/r", "http://127.0.0.1:8130"),
    ]


def test_run_evaluation_runs_render_target_when_playwright_available(monkeypatch):
    calls: list[tuple] = []

    def fake_run_scan(url, **kwargs):
        calls.append(("url", url))
        return _fake_result(url)

    monkeypatch.setattr(
        harness,
        "load_targets",
        lambda: [
            {"name": "spa", "url": "http://127.0.0.1:9998/", "requires_render": True, "expect": []},
        ],
    )
    monkeypatch.setattr(harness, "Store", lambda path: None)
    monkeypatch.setattr(harness, "_ensure_fixture", lambda spec: None)
    monkeypatch.setattr(harness, "run_scan", fake_run_scan)
    monkeypatch.setattr(harness.render, "is_available", lambda: True)

    report = harness.run_evaluation()

    assert [row["name"] for row in report["targets"]] == ["spa"]
    assert calls == [("url", "http://127.0.0.1:9998/")]
