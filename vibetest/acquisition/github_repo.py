"""Public GitHub repository download + artifact mapping (repo-mode acquisition).

PASSIVE by design: downloads a PUBLIC repository archive only. It never contacts
the deployed website; only the configured GitHub base URL (github.com by
default) is contacted, and only for the archive download itself.

Security notes:
- only github.com URLs / `owner/name` references are accepted (never an
  arbitrary host), so this cannot be abused as a web fetcher;
- archive download is size-capped, extraction is path-traversal-safe
  (`filter="data"`) and capped in file count and total size.
"""
from __future__ import annotations

import io
import logging
import re
import tarfile
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..core.http_util import read_bounded
from ..schemas.artifacts import Artifact, JSBundle
from . import fingerprint

logger = logging.getLogger(__name__)

_MAX_ARCHIVE_BYTES = 50_000_000
_MAX_MEMBERS = 5_000
_MAX_EXTRACTED_BYTES = 200_000_000

_MAX_FILES = 400
_MAX_FILE_BYTES = 262_144
_MAX_LOCKFILE_BYTES = 1_500_000
_MAX_TOTAL_TEXT_BYTES = 8_000_000

_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", "vendor",
    "__pycache__", ".venv", "venv", "coverage",
}
_SPECIAL_NAMES = {"Dockerfile", ".npmrc", ".pypirc", ".gitignore", "yarn.lock"}
_LOCKFILE_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
_TEXT_EXTENSIONS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".html", ".htm", ".css", ".scss", ".json", ".yml", ".yaml", ".toml",
    ".ini", ".cfg", ".conf", ".txt", ".md", ".sh", ".ps1", ".py", ".rb",
    ".go", ".php", ".java", ".lock",
}
_OWNER_RE = re.compile(r"^[A-Za-z0-9-]+$")  # GitHub owners: letters, digits, hyphens
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+$")  # repo names may also contain . and _


def parse_repo_ref(text: str) -> tuple[str, str]:
    """Accept `owner/name`, `github.com/owner/name` or a full github.com URL.

    Returns (owner, repo). Raises ValueError for anything else.
    """
    raw = text.strip()
    if "://" in raw or raw.lower().startswith("github.com"):
        parts = urlsplit(raw if "://" in raw else "https://" + raw)
        if parts.netloc.lower() not in ("github.com", "www.github.com"):
            raise ValueError("only github.com repositories are supported")
        raw = parts.path
    raw = raw.strip("/")
    if raw.endswith(".git"):
        raw = raw[:-4]
    segments = [s for s in raw.split("/") if s]
    if len(segments) < 2:
        raise ValueError("expected a repository like 'owner/name' or a github.com URL")
    owner, repo = segments[0], segments[1]
    if not _OWNER_RE.match(owner) or not _REPO_RE.match(repo):
        # e.g. a pasted foreign host like "gitlab.com/o/r" must not be treated
        # as owner "gitlab.com" — reject so callers can fall back / error clearly
        raise ValueError("expected a repository like 'owner/name' or a github.com URL")
    return owner, repo


def download_repo(
    owner: str,
    repo: str,
    *,
    branch: str | None,
    base_url: str,
    client: httpx.Client,
    user_agent: str,
) -> tuple[bytes, str]:
    """Download the repository archive. Tries the given branch, else main/master."""
    branches = [branch] if branch else ["main", "master"]
    errors: list[str] = []
    for candidate in branches:
        url = f"{base_url.rstrip('/')}/{owner}/{repo}/archive/refs/heads/{candidate}.tar.gz"
        try:
            with client.stream("GET", url, headers={"User-Agent": user_agent}) as resp:
                if resp.status_code != 200:
                    errors.append(f"{candidate}: HTTP {resp.status_code}")
                    continue
                data = read_bounded(resp, _MAX_ARCHIVE_BYTES)
        except httpx.HTTPError as exc:
            errors.append(f"{candidate}: {exc}")
            continue
        return data, candidate
    raise RuntimeError("could not download the repository archive (" + "; ".join(errors) + ")")


def extract_repo(archive: bytes, dest: Path) -> Path:
    """Safely extract an archive, stripping the top-level `repo-branch/` folder."""
    dest.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            members = []
            total = 0
            for member in tf.getmembers():
                if len(members) >= _MAX_MEMBERS:
                    logger.warning("archive member limit reached (%d) — truncating", _MAX_MEMBERS)
                    break
                total += member.size
                if total > _MAX_EXTRACTED_BYTES:
                    raise RuntimeError("repository archive is too large after extraction")
                name = member.name.split("/", 1)[1] if "/" in member.name else ""
                if not name:
                    continue
                member.name = name
                members.append(member)
            tf.extractall(dest, members=members, filter="data")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError(f"could not extract the repository archive: {exc}") from exc
    return dest


def _is_text_candidate(name: str) -> bool:
    if name in _SPECIAL_NAMES or name.startswith(".env"):
        return True
    return Path(name).suffix.lower() in _TEXT_EXTENSIONS


def _file_cap(name: str) -> int:
    return _MAX_LOCKFILE_BYTES if name in _LOCKFILE_NAMES else _MAX_FILE_BYTES


def build_repo_artifact(root: Path, *, repo_url: str, branch: str) -> Artifact:
    """Map repository text files into the standard Artifact (js_bundles)."""
    bundles: list[JSBundle] = []
    errors: list[str] = []
    total_text = 0
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        parts = rel.split("/")
        if any(part in _SKIP_DIRS for part in parts):
            continue
        name = parts[-1]
        if not _is_text_candidate(name):
            continue
        if len(bundles) >= _MAX_FILES:
            errors.append(f"file limit reached ({_MAX_FILES}) — remaining files skipped")
            break
        if total_text >= _MAX_TOTAL_TEXT_BYTES:
            errors.append("total text size limit reached — remaining files skipped")
            break
        try:
            if path.stat().st_size > _file_cap(name):
                errors.append(f"skipped (too large): {rel}")
                continue
            raw = path.read_bytes()
            if b"\x00" in raw:
                continue  # binary content (null bytes) — never text-scanned
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # unreadable or binary — not a text source file
        bundles.append(JSBundle(url=rel, content=text))
        total_text += len(text)

    return Artifact(
        target_url=repo_url,
        js_bundles=bundles,
        tech=fingerprint.detect([], bundles),
        errors=errors,
    )
