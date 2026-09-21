"""VibeTest CLI (Typer). Primary delivery format — see PROJECTS.md §5."""
from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from .config import load_settings
from .core.consent import ConsentDenied, ConsentGate
from .core.orchestrator import run_scan
from .core.repo_scan import run_repo_scan
from .core.store import Store
from .reporting.html_report import render_report
from .schemas.scan import ScanResult

app = typer.Typer(
    help="VibeTest — authorization-gated security scanner for vibe-coded web apps.",
    no_args_is_help=True,
)
console = Console()

_SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def _print_findings(result: ScanResult) -> None:
    table = Table(title=f"VibeTest scan — {result.target_url}")
    for col in ("Severity", "Title", "Category", "CWE", "OWASP"):
        table.add_column(col)
    for f in result.findings:
        table.add_row(
            f.severity.value.upper(),
            f.title,
            f.category,
            f.cwe_id or "-",
            f.owasp_2025 or "-",
            style=_SEVERITY_STYLE.get(f.severity.value, ""),
        )
    console.print(table)
    tech = result.artifact.tech
    known = [part for part in [tech.framework, tech.hosting, *tech.backend_services] if part]
    if known:
        console.print(f"Detected technology: {' · '.join(known)}")
    console.print(f"{len(result.findings)} finding(s). Scan id: {result.scan_id}")


def _write_report(result: ScanResult, out: Path | None) -> None:
    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(render_report(result), encoding="utf-8")
        console.print(f"HTML report written to {out}")


@app.command()
def scan(
    url: str = typer.Argument(..., help="Target URL. MUST be on the allowlist (owned/authorized only)."),
    allow: list[str] = typer.Option([], "--allow", help="Add a hostname to the allowlist for this run."),
    no_llm: bool = typer.Option(True, "--no-llm/--llm", help="Template explanations (default) or local Ollama model (falls back to templates if unavailable)."),
    no_probes: bool = typer.Option(False, "--no-probes", help="Passive-only scan: skip gentle probe checks (exposed files, ...)."),
    no_render: bool = typer.Option(False, "--no-render", help="Skip headless rendering of JavaScript-built pages."),
    out: Path | None = typer.Option(None, "--out", help="Write a self-contained HTML report to this path."),
    no_db: bool = typer.Option(False, "--no-db", help="Do not persist the scan to SQLite."),
) -> None:
    settings = load_settings()
    if no_probes:
        settings = settings.model_copy(update={"enable_probes": False})
    if no_render:
        settings = settings.model_copy(update={"render_spa": False})
    if not no_llm:
        console.print(
            f"[dim]LLM explanations: local Ollama model '{settings.ollama_model}' "
            "(template fallback if unavailable).[/]"
        )
    gate = ConsentGate([*settings.allowed_targets, *allow])
    store = None if no_db else Store(settings.database_path)
    try:
        result = run_scan(url, settings=settings, gate=gate, no_llm=no_llm, store=store)
    except ConsentDenied as exc:
        console.print(f"[bold red]REFUSED:[/] {exc}")
        raise typer.Exit(code=2) from exc

    _print_findings(result)
    _write_report(result, out)


@app.command("scan-repo")
def scan_repo(
    repo: str = typer.Argument(..., help="owner/name or a github.com URL. PUBLIC repositories only (static analysis)."),
    branch: str | None = typer.Option(None, "--branch", help="Branch to download (default: main, then master)."),
    github_base: str | None = typer.Option(None, "--github-base", help="GitHub base URL override (for mirrors/testing)."),
    no_llm: bool = typer.Option(True, "--no-llm/--llm", help="Template explanations (default) or local Ollama model."),
    out: Path | None = typer.Option(None, "--out", help="Write a self-contained HTML report to this path."),
    no_db: bool = typer.Option(False, "--no-db", help="Do not persist the scan to SQLite."),
) -> None:
    """Scan a PUBLIC GitHub repository (static analysis — no live testing)."""
    settings = load_settings()
    if not no_llm:
        console.print(
            f"[dim]LLM explanations: local Ollama model '{settings.ollama_model}' "
            "(template fallback if unavailable).[/]"
        )
    store = None if no_db else Store(settings.database_path)
    try:
        result = run_repo_scan(
            repo,
            settings=settings,
            branch=branch,
            github_base=github_base,
            no_llm=no_llm,
            store=store,
        )
    except ValueError as exc:
        console.print(f"[bold red]INVALID REPOSITORY:[/] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        console.print(f"[bold red]DOWNLOAD FAILED:[/] {exc}")
        raise typer.Exit(code=1) from exc

    _print_findings(result)
    _write_report(result, out)


@app.command()
def targets() -> None:
    """List the allowlisted (owned/authorized) targets."""
    settings = load_settings()
    console.print("Allowlisted targets (owned/authorized only):")
    for t in settings.allowed_targets:
        console.print(f"  • {t}")


@app.command()
def serve(
    port: int = typer.Option(8000, "--port", help="Port to serve on (localhost only)."),
    db: Path | None = typer.Option(None, "--db", help="SQLite database path (default: from vibetest.toml)."),
) -> None:
    """Local dashboard: start consent-gated scans and browse past results."""
    import uvicorn

    from .web.app import create_app

    settings = load_settings()
    db_path = str(db) if db is not None else settings.database_path
    console.print(f"VibeTest dashboard on [bold]http://127.0.0.1:{port}/[/] — Ctrl+C to stop")
    uvicorn.run(create_app(db_path), host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    app()
