"""GitHub-repository scan mode — static analysis of PUBLIC repositories.

Downloads a public repository archive, maps its source files into the standard
Artifact, and runs the detector registry over it. No requests are ever made to
the deployed website; only the GitHub base URL (archive download) and the free
OSV.dev service (dependency lookups) are contacted.
"""
from __future__ import annotations

import logging
import tempfile
from pathlib import Path

import httpx

from ..acquisition.github_repo import build_repo_artifact, download_repo, extract_repo, parse_repo_ref
from ..analysis.aggregate import dedup, sort_by_severity
from ..config import Settings
from ..core.consent import ConsentGate
from ..core.context import ScanContext
from ..core.orchestrator import run_detectors
from ..core.store import Store
from ..reporting.explain import apply_explanations
from ..schemas.scan import ScanResult

logger = logging.getLogger(__name__)


def run_repo_scan(
    ref: str,
    *,
    settings: Settings,
    branch: str | None = None,
    github_base: str | None = None,
    no_llm: bool = True,
    store: Store | None = None,
    client: httpx.Client | None = None,
    detector_ids: list[str] | None = None,
) -> ScanResult:
    """Download a public repository and analyze it statically.

    Raises ValueError for an invalid reference and RuntimeError when the
    archive cannot be downloaded or extracted.
    """
    owner, repo = parse_repo_ref(ref)
    base = (github_base or settings.github_base).rstrip("/")

    owns_client = client is None
    if client is None:
        client = httpx.Client(
            follow_redirects=True,  # github.com redirects archives to codeload
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent},
        )
    try:
        archive, used_branch = download_repo(
            owner, repo, branch=branch, base_url=base, client=client, user_agent=settings.user_agent
        )
        logger.info("downloaded %s/%s (branch %s, %d bytes)", owner, repo, used_branch, len(archive))
        with tempfile.TemporaryDirectory(prefix="vibetest_repo_") as tmp:
            root = extract_repo(archive, Path(tmp))
            artifact = build_repo_artifact(
                root, repo_url=f"{base}/{owner}/{repo}", branch=used_branch
            )
            # Static analysis only: target probes stay OFF (allow_probes=False).
            # ctx.http is provided solely for the free OSV.dev dependency service.
            ctx = ScanContext(
                settings=settings,
                gate=ConsentGate(settings.allowed_targets),
                allow_probes=False,
                http=client if settings.osv_api_url else None,
            )
            findings = run_detectors(artifact, ctx, detector_ids)
    finally:
        if owns_client:
            client.close()

    findings = sort_by_severity(dedup(findings))
    apply_explanations(findings, mode="template" if no_llm else "ollama", settings=settings)

    result = ScanResult(
        scan_id=artifact.scan_id,
        target_url=artifact.target_url,
        started_at=artifact.fetched_at,
        artifact=artifact,
        findings=findings,
    )
    if store is not None:
        store.save_scan(result)
    return result
