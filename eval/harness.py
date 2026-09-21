"""Evaluation harness — precision/recall against the owned demo targets.

Starts the local fixtures when needed, runs the full scan pipeline against each
target in `eval/targets.yaml`, compares the findings with the planted
ground-truth labels, and writes the paper's evaluation numbers to
`eval/results.json` and `eval/results.md`.

Metrics are CATEGORY-LEVEL (one ground-truth item = one expected finding
category per target):
    TP = expected categories that fired
    FP = categories that fired but were not expected
    FN = expected categories that did not fire

`forbid_*` entries are precision guardrails: checks that must NOT fire
(e.g. the public anon key must never be reported as a secret).

Target specs support:
- `mode: repo` — scanned with `run_repo_scan` (default is URL mode);
- `requires_render: true` — target skipped with a note when Playwright is absent;
- `ready_url` — readiness check when the target has no scan `url` (repo mode).

Usage:  .venv\\Scripts\\python.exe eval\\harness.py
Requires: internet for the OSV dependency lookups (demo_site, demo_repo).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
import yaml
from rich.console import Console
from rich.table import Table

from vibetest.acquisition import render
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.orchestrator import run_scan
from vibetest.core.repo_scan import run_repo_scan
from vibetest.core.store import Store
from vibetest.schemas.scan import ScanResult

ROOT = Path(__file__).resolve().parent.parent
TARGETS_FILE = ROOT / "eval" / "targets.yaml"
RESULTS_JSON = ROOT / "eval" / "results.json"
RESULTS_MD = ROOT / "eval" / "results.md"

console = Console()


def load_targets(path: Path = TARGETS_FILE) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return list(data.get("targets") or [])


def evaluate(result: ScanResult, spec: dict) -> dict:
    """Compare one scan's findings with its ground-truth spec (pure function)."""
    expected = set(spec.get("expect") or [])
    found = {f.category for f in result.findings}
    tp = expected & found
    fp = found - expected
    fn = expected - found

    violations: list[str] = []
    for category in sorted(found & set(spec.get("forbid_categories") or [])):
        violations.append(f"forbidden category present: {category}")
    for needle in spec.get("forbid_title_contains") or []:
        for finding in result.findings:
            if needle.lower() in finding.title.lower():
                violations.append(f"forbidden title present: {finding.title!r} (matched {needle!r})")

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "name": spec.get("name", result.target_url),
        "url": result.target_url,
        "findings": len(result.findings),
        "tp": sorted(tp),
        "fp": sorted(fp),
        "fn": sorted(fn),
        "violations": violations,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def _ready_url(spec: dict) -> str:
    """URL used to check that a fixture is up (falls back to the scan URL)."""
    return spec.get("ready_url") or spec.get("url", "")


def _start_fixture(spec: dict) -> subprocess.Popen | None:
    if "fixture_dir" in spec:
        cmd = [
            sys.executable, "-m", "http.server", str(spec["port"]),
            "--bind", "127.0.0.1", "--directory", str(ROOT / spec["fixture_dir"]),
        ]
    elif "fixture_script" in spec:
        cmd = [sys.executable, str(ROOT / spec["fixture_script"])]
    else:
        return None
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT))
    ready = _ready_url(spec)
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"fixture for {spec.get('name')} exited early (code {proc.returncode})")
        try:
            httpx.get(ready, timeout=1.0)
            return proc
        except httpx.HTTPError:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError(f"fixture for {spec.get('name')} not ready after 15s: {ready}")


def _ensure_fixture(spec: dict) -> subprocess.Popen | None:
    """Start the fixture unless its readiness URL is already being served."""
    try:
        httpx.get(_ready_url(spec), timeout=1.0)
        return None  # something is already serving it — leave it alone
    except httpx.HTTPError:
        return _start_fixture(spec)


def _scan_target(spec: dict, settings: Settings, gate: ConsentGate, store: Store | None) -> ScanResult:
    """Dispatch to the right pipeline: repo mode or URL mode."""
    if spec.get("mode") == "repo":
        return run_repo_scan(
            spec["repo"],
            settings=settings,
            github_base=spec.get("github_base"),
            no_llm=True,
            store=store,
        )
    return run_scan(spec["url"], settings=settings, gate=gate, no_llm=True, store=store)


def run_evaluation() -> dict:
    targets = load_targets()
    settings = Settings()
    gate = ConsentGate([*settings.allowed_targets, "127.0.0.1", "localhost"])
    store = Store(str(ROOT / "eval" / "eval.db"))
    rows: list[dict] = []
    render_ready = render.is_available()

    for spec in targets:
        label = spec.get("url") or spec.get("repo") or spec["name"]
        if spec.get("requires_render") and not render_ready:
            console.print(
                f"[yellow]Skipping[/] {spec['name']} @ {label} — Playwright not installed "
                '(pip install -e ".[crawl]" + playwright install chromium)'
            )
            continue
        proc = None
        try:
            proc = _ensure_fixture(spec)
            console.print(f"[bold]Scanning[/] {spec['name']} @ {label}")
            result = _scan_target(spec, settings, gate, store)
        finally:
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        rows.append(evaluate(result, spec))

    tp = sum(len(r["tp"]) for r in rows)
    fp = sum(len(r["fp"]) for r in rows)
    fn = sum(len(r["fn"]) for r in rows)
    precision = tp / (tp + fp) if (tp or fp) else 1.0
    recall = tp / (tp + fn) if (tp or fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "targets": rows,
        "overall": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "violations_total": sum(len(r["violations"]) for r in rows),
        },
    }


def _print_report(report: dict) -> None:
    table = Table(title="VibeTest evaluation — owned targets")
    for col in ("Target", "Findings", "TP", "FP", "FN", "Violations", "Precision", "Recall", "F1"):
        table.add_column(col)
    for r in report["targets"]:
        table.add_row(
            r["name"], str(r["findings"]), str(len(r["tp"])), str(len(r["fp"])), str(len(r["fn"])),
            str(len(r["violations"])), f"{r['precision']:.2f}", f"{r['recall']:.2f}", f"{r['f1']:.2f}",
        )
    console.print(table)
    o = report["overall"]
    console.print(
        f"Overall (category-level): P={o['precision']:.2f} R={o['recall']:.2f} F1={o['f1']:.2f} "
        f"| constraint violations: {o['violations_total']}"
    )


def _write_markdown(report: dict) -> None:
    lines = [
        "# VibeTest evaluation results",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "| Target | Findings | TP | FP | FN | Violations | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in report["targets"]:
        lines.append(
            f"| {r['name']} | {r['findings']} | {len(r['tp'])} | {len(r['fp'])} | {len(r['fn'])} "
            f"| {len(r['violations'])} | {r['precision']:.2f} | {r['recall']:.2f} | {r['f1']:.2f} |"
        )
    o = report["overall"]
    lines += [
        "",
        f"**Overall (category-level):** precision {o['precision']:.2f} · recall {o['recall']:.2f} · "
        f"F1 {o['f1']:.2f} · constraint violations: {o['violations_total']}",
        "",
        "Missing (FN) / unexpected (FP) details are in `eval/results.json`.",
    ]
    RESULTS_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    report = run_evaluation()
    _print_report(report)
    RESULTS_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_markdown(report)
    console.print(f"Wrote {RESULTS_JSON.relative_to(ROOT)} and {RESULTS_MD.relative_to(ROOT)}")
    if report["overall"]["violations_total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
