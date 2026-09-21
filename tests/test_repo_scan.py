"""Repo-mode tests (download/extract/mapping/detectors) — no real network."""
import io
import json
import tarfile

import pytest

from fake_http import FakeClient, FakeStreamResponse
from vibetest.acquisition import github_repo
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext
from vibetest.core.repo_scan import run_repo_scan
from vibetest.detectors import repo_deps
from vibetest.detectors.repo_deps import RepoDepsDetector
from vibetest.detectors.repo_sensitive_files import RepoSensitiveFilesDetector
from vibetest.schemas.artifacts import Artifact, JSBundle
from vibetest.schemas.findings import Severity

TARBALL_URL = "https://gh.test/o/r/archive/refs/heads/main.tar.gz"
MASTER_URL = "https://gh.test/o/r/archive/refs/heads/master.tar.gz"

LOCK = json.dumps(
    {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"}},
    }
).encode()

ENV_FILE = b"SUPABASE_SERVICE_KEY=demo_secret_123\nDEBUG=true\n"


def _make_tar(files: dict[str, bytes], top: str = "r-main") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _artifact_with(files: dict[str, str]) -> Artifact:
    return Artifact(
        target_url="repo",
        js_bundles=[JSBundle(url=name, content=content) for name, content in files.items()],
    )


def _ctx(http=None) -> ScanContext:
    return ScanContext(settings=Settings(), gate=ConsentGate(["localhost"]), allow_probes=False, http=http)


# ------------------------------------------------------------------ repo refs

def test_parse_repo_ref_variants():
    assert github_repo.parse_repo_ref("owner/name") == ("owner", "name")
    assert github_repo.parse_repo_ref("https://github.com/owner/name") == ("owner", "name")
    assert github_repo.parse_repo_ref("github.com/owner/name.git") == ("owner", "name")
    assert github_repo.parse_repo_ref("owner/name/") == ("owner", "name")


def test_parse_repo_ref_rejects_other_hosts_and_garbage():
    with pytest.raises(ValueError):
        github_repo.parse_repo_ref("https://gitlab.com/owner/name")
    with pytest.raises(ValueError):
        github_repo.parse_repo_ref("just-one-segment")


# ------------------------------------------------------ download and extract

def test_download_and_extract_roundtrip(tmp_path):
    archive = _make_tar({"README.md": b"hi", "src/app.js": b"const x = 1;"})
    client = FakeClient({TARBALL_URL: FakeStreamResponse(200, {}, archive)})
    data, branch = github_repo.download_repo(
        "o", "r", branch=None, base_url="https://gh.test", client=client, user_agent="t"
    )
    assert branch == "main"
    root = github_repo.extract_repo(data, tmp_path)
    assert (root / "src" / "app.js").read_text(encoding="utf-8") == "const x = 1;"
    assert (root / "README.md").exists()


def test_download_falls_back_to_master():
    archive = _make_tar({"a.js": b"x"})
    client = FakeClient({MASTER_URL: FakeStreamResponse(200, {}, archive)})
    data, branch = github_repo.download_repo(
        "o", "r", branch=None, base_url="https://gh.test", client=client, user_agent="t"
    )
    assert branch == "master"
    assert client.calls == [TARBALL_URL, MASTER_URL]


# ------------------------------------------------------- artifact mapping

def test_build_repo_artifact_maps_text_files(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text('const u = "https://demo.supabase.co";', encoding="utf-8")
    (tmp_path / ".env").write_text("KEY=value\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps({"lockfileVersion": 3, "packages": {}}), encoding="utf-8"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.js").write_text("x", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n")

    artifact = github_repo.build_repo_artifact(tmp_path, repo_url="https://github.com/o/r", branch="main")
    urls = {b.url for b in artifact.js_bundles}
    assert "src/app.js" in urls
    assert ".env" in urls
    assert "package-lock.json" in urls
    assert "node_modules/skip.js" not in urls
    assert "logo.png" not in urls
    assert artifact.tech.backend_services == ["supabase"]
    assert artifact.target_url == "https://github.com/o/r"


def test_build_repo_artifact_skips_binary_and_oversized(tmp_path):
    (tmp_path / "blob.js").write_bytes(b"\x00\x01\x02binary")
    (tmp_path / "big.js").write_text("a" * 300_000, encoding="utf-8")
    (tmp_path / "ok.js").write_text("const ok = 1;", encoding="utf-8")

    artifact = github_repo.build_repo_artifact(tmp_path, repo_url="u", branch="main")
    assert {b.url for b in artifact.js_bundles} == {"ok.js"}
    assert any("too large" in error for error in artifact.errors)


# ------------------------------------------------------- repo detectors

def test_repo_sensitive_files_flags_env_and_service_account():
    artifact = _artifact_with(
        {
            ".env": "API_KEY=secret123\n",
            "serviceAccountKey.json": '{"type": "service_account"}',
            "src/app.js": "const x = 1;",
        }
    )
    findings = RepoSensitiveFilesDetector().run(artifact, _ctx())
    titles = {f.title for f in findings}
    assert any(".env" in t for t in titles)
    assert any("serviceAccountKey.json" in t for t in titles)
    assert len(findings) == 2  # app.js is not sensitive

    env_finding = next(f for f in findings if ".env" in f.title)
    assert env_finding.severity is Severity.CRITICAL
    assert "secret123" not in env_finding.evidence[0].snippet
    assert "API_KEY=***" in env_finding.evidence[0].snippet


def test_repo_sensitive_files_ignores_absolute_urls():
    artifact = Artifact(
        target_url="http://localhost:8000/",
        js_bundles=[JSBundle(url="http://localhost:8000/.env", content="KEY=1\n")],
    )
    assert RepoSensitiveFilesDetector().run(artifact, _ctx()) == []


def test_repo_deps_reports_vulnerable_lockfile(monkeypatch):
    def fake_query(client, api_url, name, version, ecosystem="npm"):
        if name == "lodash":
            return [
                {
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "aliases": ["CVE-2020-8203"],
                    "summary": "Prototype pollution",
                    "database_specific": {"severity": "HIGH"},
                }
            ]
        return []

    monkeypatch.setattr(repo_deps, "query_osv", fake_query)
    artifact = _artifact_with({"package-lock.json": LOCK.decode()})
    findings = RepoDepsDetector().run(artifact, _ctx(http=FakeClient()))

    assert len(findings) == 1
    f = findings[0]
    assert "lodash@4.17.15" in f.title
    assert f.severity is Severity.HIGH
    assert f.evidence[0].url == "package-lock.json"


def test_repo_deps_disabled_without_osv():
    artifact = _artifact_with({"package-lock.json": LOCK.decode()})
    ctx = ScanContext(settings=Settings(osv_api_url=""), gate=ConsentGate(["localhost"]), http=FakeClient())
    assert RepoDepsDetector().run(artifact, ctx) == []


# ------------------------------------------------------- end to end

def test_run_repo_scan_end_to_end(tmp_path, monkeypatch):
    files = {
        ".env": ENV_FILE,
        "src/app.js": b'const SUPABASE_URL = "https://demo-project.supabase.co";',
        "package-lock.json": LOCK,
    }
    client = FakeClient({TARBALL_URL: FakeStreamResponse(200, {}, _make_tar(files))})

    def fake_query(client_, api_url, name, version, ecosystem="npm"):
        if name == "lodash":
            return [{"id": "GHSA-x", "aliases": [], "summary": "", "database_specific": {"severity": "HIGH"}}]
        return []

    monkeypatch.setattr(repo_deps, "query_osv", fake_query)
    settings = Settings(github_base="https://gh.test", llm_cache_path=str(tmp_path / "cache.json"))

    result = run_repo_scan("o/r", settings=settings, client=client, no_llm=True)

    categories = {f.category for f in result.findings}
    assert "exposed-sensitive-file" in categories  # committed .env
    assert "vulnerable-dependency" in categories  # lodash via (fake) OSV
    assert result.target_url == "https://gh.test/o/r"
    assert all(f.explanation for f in result.findings)
