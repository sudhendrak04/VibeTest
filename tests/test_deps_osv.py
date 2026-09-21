"""Vulnerable-dependencies detector tests (fake HTTP client — no network)."""
import json

from fake_http import FakeClient, FakeStreamResponse
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.detectors import deps_osv
from vibetest.detectors.deps_osv import DepsOSVDetector
from vibetest.schemas.artifacts import Artifact, PageSnapshot
from vibetest.schemas.findings import Severity

BASE = "http://localhost:8000/"

LOCK = json.dumps(
    {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15"},
            "node_modules/minimist": {"version": "1.2.0"},
        },
    }
).encode()


def _artifact() -> Artifact:
    return Artifact(target_url=BASE, pages=[PageSnapshot(url=BASE, status_code=200, headers={}, html="")])


def _ctx(client, **settings_kwargs) -> ScanContext:
    return ScanContext(
        settings=Settings(**settings_kwargs),
        gate=ConsentGate(["localhost"]),
        allow_probes=True,
        http=client,
    )


# ------------------------------------------------------------------ parsers

def test_parse_package_lock_v3():
    pairs = deps_osv.parse_manifest("/package-lock.json", LOCK.decode())
    assert ("lodash", "4.17.15") in pairs
    assert ("minimist", "1.2.0") in pairs


def test_parse_package_lock_v1_recursive():
    text = json.dumps(
        {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {"version": "4.17.15", "dependencies": {"nested": {"version": "1.0.0"}}}
            },
        }
    )
    pairs = deps_osv.parse_manifest("/package-lock.json", text)
    assert ("lodash", "4.17.15") in pairs
    assert ("nested", "1.0.0") in pairs


def test_parse_package_json_skips_ranges():
    text = json.dumps({"dependencies": {"lodash": "^4.17.0", "axios": "0.21.1"}})
    pairs = deps_osv.parse_manifest("/package.json", text)
    assert pairs == [("axios", "0.21.1")]


def test_parse_yarn_lock():
    text = 'lodash@^4.17.20:\n  version "4.17.21"\n\n@scope/pkg@^2.0.0:\n  version "2.1.0"\n'
    pairs = deps_osv.parse_manifest("/yarn.lock", text)
    assert ("lodash", "4.17.21") in pairs
    assert ("@scope/pkg", "2.1.0") in pairs


def test_parse_pnpm_lock():
    text = (
        "lockfileVersion: '6.0'\n"
        "packages:\n"
        "  /lodash@4.17.21:\n"
        "    resolution: {integrity: sha}\n"
        "  '@scope/pkg@2.1.0':\n"
        "    resolution: {integrity: sha}\n"
    )
    pairs = deps_osv.parse_manifest("/pnpm-lock.yaml", text)
    assert ("lodash", "4.17.21") in pairs
    assert ("@scope/pkg", "2.1.0") in pairs


# ------------------------------------------------------------------ behavior

def test_manifest_and_vulnerable_dependency_reported(monkeypatch):
    calls: list[tuple[str, str]] = []

    def fake_query(client, api_url, name, version, ecosystem="npm"):
        calls.append((name, version))
        if name == "lodash":
            return [
                {
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "aliases": ["CVE-2020-8203"],
                    "summary": "Prototype pollution in lodash",
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        return []

    monkeypatch.setattr(deps_osv, "query_osv", fake_query)
    client = FakeClient(
        {BASE + "package-lock.json": FakeStreamResponse(200, {"content-type": "application/json"}, LOCK)}
    )
    findings = DepsOSVDetector().run(_artifact(), _ctx(client))

    assert {f.category for f in findings} == {"exposed-sensitive-file", "vulnerable-dependency"}
    vuln = next(f for f in findings if f.category == "vulnerable-dependency")
    assert "lodash@4.17.15" in vuln.title
    assert vuln.severity is Severity.HIGH
    assert "GHSA-35jh-r3h4-6jhm" in vuln.evidence[0].snippet
    assert "CVE-2020-8203" in vuln.evidence[0].snippet
    assert calls == [("lodash", "4.17.15"), ("minimist", "1.2.0")]


def test_osv_disabled_reports_only_manifest_exposure(monkeypatch):
    def boom(*args, **kwargs):
        raise AssertionError("OSV must not be called when disabled")

    monkeypatch.setattr(deps_osv, "query_osv", boom)
    client = FakeClient(
        {BASE + "package-lock.json": FakeStreamResponse(200, {"content-type": "application/json"}, LOCK)}
    )
    findings = DepsOSVDetector().run(_artifact(), _ctx(client, osv_api_url=""))
    assert len(findings) == 1
    assert findings[0].severity is Severity.LOW
    assert "manifest" in findings[0].title.lower()


def test_spa_fallback_html_manifest_ignored():
    client = FakeClient(
        {
            BASE + "package-lock.json": FakeStreamResponse(
                200, {"content-type": "text/html"}, b"<!DOCTYPE html><html></html>"
            )
        }
    )
    assert DepsOSVDetector().run(_artifact(), _ctx(client)) == []


def test_non_allowlisted_host_makes_no_requests():
    client = FakeClient()
    ctx = ScanContext(
        settings=Settings(),
        gate=ConsentGate(["some-other-host.test"]),
        allow_probes=True,
        http=client,
    )
    assert DepsOSVDetector().run(_artifact(), ctx) == []
    assert client.calls == []


def test_large_osv_response_is_not_truncated():
    """Regression: real OSV responses can exceed 200 KB (e.g. axios@0.21.1);
    a too-small read limit used to silently truncate the JSON and drop findings."""
    big = json.dumps(
        {
            "vulns": [
                {
                    "id": f"GHSA-large-{i}",
                    "aliases": [],
                    "summary": "s" * 4000,
                    "database_specific": {"severity": "HIGH"},
                }
                for i in range(30)
            ]
        }
    ).encode()
    assert len(big) > 65536  # must exceed the old 64 KB limit to be a real regression test

    client = FakeClient(
        {
            BASE + "package-lock.json": FakeStreamResponse(200, {"content-type": "application/json"}, LOCK),
            "https://osv.test/v1/query": FakeStreamResponse(200, {"content-type": "application/json"}, big),
        }
    )
    findings = DepsOSVDetector().run(
        _artifact(), _ctx(client, osv_api_url="https://osv.test/v1/query")
    )
    vuln = next(f for f in findings if f.category == "vulnerable-dependency")
    assert "(30 known advisories)" in vuln.title
