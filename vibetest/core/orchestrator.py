"""The pipeline runner. Fetcher and probe client are injectable so tests never
touch the network."""
from __future__ import annotations

from collections.abc import Callable

import httpx

from ..acquisition import crawler
from ..analysis.aggregate import dedup, sort_by_severity
from ..config import Settings
from ..detectors import registry
from ..reporting.explain import apply_explanations
from ..schemas.artifacts import Artifact
from ..schemas.findings import Finding
from ..schemas.scan import ScanResult
from .consent import ConsentGate
from .context import ScanContext
from .store import Store

Fetcher = Callable[[str, ScanContext], Artifact]


def run_detectors(
    artifact: Artifact, ctx: ScanContext, detector_ids: list[str] | None = None
) -> list[Finding]:
    """Run all enabled detectors. Probe-based detectors only when probes are allowed."""
    findings: list[Finding] = []
    for detector in registry.enabled(detector_ids):
        if detector.needs_probes and not ctx.allow_probes:
            continue
        findings.extend(detector.run(artifact, ctx))
    return findings


def run_scan(
    url: str,
    *,
    settings: Settings,
    gate: ConsentGate,
    fetcher: Fetcher | None = None,
    detector_ids: list[str] | None = None,
    no_llm: bool = True,
    store: Store | None = None,
    http_client: httpx.Client | None = None,
) -> ScanResult:
    # 1. CONSENT GATE — before any request to the target. No exceptions.
    gate.check(url)

    # 2. Probe client: gentle extra requests (exposed files, later Supabase RLS).
    #    Safe because scans only ever run against allowlisted targets, and every
    #    probe URL is consent-checked again inside each detector.
    owns_client = False
    probe_client = http_client
    if settings.enable_probes and probe_client is None:
        probe_client = httpx.Client(
            follow_redirects=False,  # a redirect is not an exposure
            timeout=settings.request_timeout,
            headers={"User-Agent": settings.user_agent},
        )
        owns_client = True

    # 3. Acquisition → Artifact (CONTRACT 1)
    ctx = ScanContext(
        settings=settings,
        gate=gate,
        allow_probes=settings.enable_probes,
        http=probe_client,
    )
    try:
        artifact = (fetcher or crawler.fetch)(url, ctx)

        # 4. Detection → Findings (CONTRACT 2)
        findings = run_detectors(artifact, ctx, detector_ids)
    finally:
        if owns_client and probe_client is not None:
            probe_client.close()

    # 5. Analysis: dedup + severity ordering
    findings = sort_by_severity(dedup(findings))

    # 6. Explanation layer (template by default; local Ollama with --llm)
    apply_explanations(findings, mode="template" if no_llm else "ollama", settings=settings)

    # 7. Persist (scan once, re-render later)
    result = ScanResult(
        scan_id=artifact.scan_id,
        target_url=url,
        started_at=artifact.fetched_at,
        artifact=artifact,
        findings=findings,
    )
    if store is not None:
        store.save_scan(result)
    return result
