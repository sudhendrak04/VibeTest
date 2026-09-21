"""Localhost dashboard (FastAPI + Jinja2) — scan launcher + results viewer.

Safety guarantees:
- binds to 127.0.0.1 only;
- scans started here go through the SAME consent gate as the CLI: a
  non-allowlisted URL is refused before any network request is made;
- one scan at a time (single-flight), so the machine and the targets are
  never hammered.

Run:  vibetest serve   (or: python -m vibetest.web.app)
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from jinja2 import BaseLoader, Environment, select_autoescape
from pydantic import BaseModel

from ..analysis.aggregate import sort_by_severity
from ..config import Settings, load_settings
from ..core.consent import ConsentDenied, ConsentGate
from ..core.orchestrator import run_scan
from ..core.store import Store
from ..reporting.html_report import render_report
from ..schemas.artifacts import Artifact
from ..schemas.findings import Finding
from ..schemas.scan import ScanResult
from .templates import DETAIL_BODY, LIST_BODY, PAGE

_SEVERITIES = ("critical", "high", "medium", "low", "info")

_env = Environment(loader=BaseLoader(), autoescape=select_autoescape(["html", "xml"]))


def _page(title: str, body: str) -> str:
    return _env.from_string(PAGE).render(title=title, body=body)


def _scan_view(store: Store, scan_id: str) -> dict | None:
    row = store.get_scan(scan_id)
    if row is None:
        return None
    artifact = Artifact.model_validate_json(row.artifact_json)
    findings = [Finding.model_validate_json(r.finding_json) for r in store.findings_for(scan_id)]
    tech = [
        part
        for part in [artifact.tech.framework, artifact.tech.hosting, *artifact.tech.backend_services]
        if part
    ]
    summary = {sev: sum(1 for f in findings if f.severity.value == sev) for sev in _SEVERITIES}
    summary["total"] = len(findings)
    return {
        "row": row,
        "artifact": artifact,
        "findings": sort_by_severity(findings),
        "tech": tech,
        "summary": summary,
    }


ScanRunner = Callable[[str, Settings, ConsentGate, Store], ScanResult]


def _default_runner(url: str, settings: Settings, gate: ConsentGate, store: Store) -> ScanResult:
    """Dashboard scans use template explanations for speed; use the CLI with
    --llm for local-AI explanations."""
    return run_scan(url, settings=settings, gate=gate, no_llm=True, store=store)


class ScanRequest(BaseModel):
    url: str


def create_app(db_path: str | None = None, scan_runner: ScanRunner | None = None) -> FastAPI:
    settings = load_settings()
    store = Store(db_path or settings.database_path)
    gate = ConsentGate(settings.allowed_targets)
    runner = scan_runner or _default_runner
    jobs: dict[str, dict] = {}
    jobs_lock = threading.Lock()

    app = FastAPI(title="VibeTest dashboard", docs_url=None, redoc_url=None)

    # ------------------------------------------------------------- pages

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        scans = []
        totals = {sev: 0 for sev in _SEVERITIES}
        grand_total = 0
        for row in store.list_scans():
            findings = [
                Finding.model_validate_json(r.finding_json) for r in store.findings_for(row.scan_id)
            ]
            counts = {sev: sum(1 for f in findings if f.severity.value == sev) for sev in _SEVERITIES}
            for sev in _SEVERITIES:
                totals[sev] += counts[sev]
            grand_total += len(findings)
            percents = {
                sev: round(counts[sev] / len(findings) * 100, 1) if findings else 0.0
                for sev in _SEVERITIES
            }
            scans.append({"row": row, "total": len(findings), "counts": counts, "percents": percents})
        stats = {"scans": len(scans), "total": grand_total, **totals}
        return _page("Scan history", _env.from_string(LIST_BODY).render(scans=scans, stats=stats))

    @app.get("/scan/{scan_id}", response_class=HTMLResponse)
    def scan_detail(scan_id: str) -> str:
        view = _scan_view(store, scan_id)
        if view is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return _page(view["row"].target_url, _env.from_string(DETAIL_BODY).render(**view))

    @app.get("/scan/{scan_id}/report", response_class=HTMLResponse)
    def scan_report(scan_id: str) -> str:
        view = _scan_view(store, scan_id)
        if view is None:
            raise HTTPException(status_code=404, detail="scan not found")
        result = ScanResult(
            scan_id=view["row"].scan_id,
            target_url=view["row"].target_url,
            started_at=view["row"].started_at,
            artifact=view["artifact"],
            findings=view["findings"],
        )
        return render_report(result)

    # ------------------------------------------------------------- scan API

    @app.post("/api/scan", status_code=202)
    def start_scan(request: ScanRequest) -> dict:
        url = request.url.strip()
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise HTTPException(status_code=400, detail="Please provide a full http(s) URL.")
        try:
            gate.check(url)  # SAME gate as the CLI — before any network activity
        except ConsentDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

        with jobs_lock:
            if any(job["status"] == "running" for job in jobs.values()):
                raise HTTPException(status_code=409, detail="A scan is already running — wait for it to finish.")
            job_id = uuid4().hex
            jobs[job_id] = {
                "job_id": job_id,
                "url": url,
                "status": "running",
                "scan_id": None,
                "error": None,
                "started_at": datetime.now(timezone.utc).isoformat(),
            }

        def _worker() -> None:
            try:
                result = runner(url, settings, gate, store)
                with jobs_lock:
                    jobs[job_id].update(
                        status="done",
                        scan_id=result.scan_id,
                        finished_at=datetime.now(timezone.utc).isoformat(),
                    )
            except Exception as exc:  # noqa: BLE001 — report any failure to the UI
                with jobs_lock:
                    jobs[job_id].update(
                        status="failed",
                        error=str(exc),
                        finished_at=datetime.now(timezone.utc).isoformat(),
                    )

        threading.Thread(target=_worker, daemon=True).start()
        return {"job_id": job_id, "status": "running"}

    @app.get("/api/scan/{job_id}")
    def scan_status(job_id: str) -> dict:
        with jobs_lock:
            job = jobs.get(job_id)
            if job is None:
                raise HTTPException(status_code=404, detail="unknown scan job")
            return dict(job)

    # ------------------------------------------------------------- JSON API

    @app.get("/api/scans")
    def api_scans() -> list[dict]:
        return [
            {"scan_id": r.scan_id, "target_url": r.target_url, "started_at": r.started_at.isoformat()}
            for r in store.list_scans()
        ]

    @app.get("/api/scans/{scan_id}")
    def api_scan(scan_id: str) -> dict:
        view = _scan_view(store, scan_id)
        if view is None:
            raise HTTPException(status_code=404, detail="scan not found")
        return {
            "scan_id": view["row"].scan_id,
            "target_url": view["row"].target_url,
            "started_at": view["row"].started_at.isoformat(),
            "tech": view["tech"],
            "findings": [f.model_dump() for f in view["findings"]],
        }

    return app


def main() -> None:
    import uvicorn

    print("VibeTest dashboard on http://127.0.0.1:8000/ (Ctrl+C to stop)")
    uvicorn.run(create_app(), host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
