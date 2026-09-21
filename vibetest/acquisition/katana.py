"""Katana wrapper — URL/endpoint discovery (SOFT dependency).

Katana (ProjectDiscovery, MIT) is an external Go binary. If it is not installed,
discovery returns an empty list and the crawler falls back to fetching the entry
page only — the tool never hard-fails on a missing binary.

Safety rules (see AGENTS.md coding conventions):
- runs crawl-only (no fuzzing) with a gentle rate limit;
- scoped to the exact target host (`-fs fqdn`) so it can never wander onto
  neighboring hosts (important for shared domains like *.vercel.app);
- every discovered URL is re-checked by the consent gate before anything fetches it.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field

from ..core.consent import ConsentGate
from ..core.context import ScanContext

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredURL:
    url: str
    method: str = "GET"
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)


def parse_jsonl(text: str) -> list[DiscoveredURL]:
    """Parse Katana `-jsonl` output. Defensive: field names vary across versions."""
    out: list[DiscoveredURL] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue  # non-JSON noise on stdout is skipped, never fatal
        request = obj.get("request") or {}
        response = obj.get("response") or {}
        url = request.get("endpoint") or request.get("url") or obj.get("url")
        if not url:
            continue
        headers = response.get("headers") or {}
        out.append(
            DiscoveredURL(
                url=str(url),
                method=str(request.get("method") or "GET").upper(),
                status_code=response.get("status_code"),
                headers=(
                    {str(k).lower(): str(v) for k, v in headers.items()}
                    if isinstance(headers, dict)
                    else {}
                ),
            )
        )
    return out


def allowed_only(discovered: list[DiscoveredURL], gate: ConsentGate) -> list[DiscoveredURL]:
    """Consent gate is authoritative: drop every URL whose host is not allowlisted.

    Deduplicates (order-preserving) at the same time.
    """
    seen: set[str] = set()
    kept: list[DiscoveredURL] = []
    for d in discovered:
        if d.url in seen or not gate.is_allowed(d.url):
            continue
        seen.add(d.url)
        kept.append(d)
    dropped = len(discovered) - len(kept)
    if dropped:
        logger.info("dropped %d discovered URL(s) outside the allowlist/duplicates", dropped)
    return kept


def _build_command(binary: str, url: str, ctx: ScanContext) -> list[str]:
    s = ctx.settings
    return [
        binary,
        "-u", url,
        "-jsonl",
        "-silent",
        "-fs", "fqdn",                     # exact host only — never neighboring hosts
        "-d", str(s.katana_depth),
        "-rl", str(s.katana_rate_limit),   # requests/second — keep gentle
        "-timeout", str(int(s.request_timeout)),
        "-duc",                            # skip update check (offline-friendly)
    ]


def discover(url: str, ctx: ScanContext) -> list[DiscoveredURL]:
    """Run Katana against `url`. Returns [] when the binary is missing or fails."""
    binary = shutil.which(ctx.settings.katana_bin)
    if binary is None:
        logger.info(
            "katana not found (%r) — falling back to single-page fetch",
            ctx.settings.katana_bin,
        )
        return []

    try:
        proc = subprocess.run(
            _build_command(binary, url, ctx),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=ctx.settings.katana_process_timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("katana run failed (%s) — falling back to single-page fetch", exc)
        return []

    if proc.returncode != 0:
        logger.warning("katana exited with code %s — parsing whatever it produced", proc.returncode)

    return allowed_only(parse_jsonl(proc.stdout), ctx.gate)
