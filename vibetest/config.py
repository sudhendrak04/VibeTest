"""Settings loading (vibetest.toml). See AGENTS.md for the hard constraints."""
from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, Field

DEFAULT_CONFIG_PATH = Path("vibetest.toml")


class Settings(BaseModel):
    # CONSENT: owned/authorized targets ONLY. The consent gate refuses everything else.
    allowed_targets: list[str] = Field(default_factory=lambda: ["localhost", "127.0.0.1"])
    ollama_model: str = "qwen3:8b"
    ollama_fallback_model: str = "phi4-mini"
    # Local LLM (Ollama) explanation layer. Without Ollama the scanner falls
    # back to template explanations automatically; --llm enables this mode.
    ollama_api_url: str = "http://127.0.0.1:11434"
    ollama_timeout: float = 120.0
    llm_cache_path: str = ".llm_cache.json"
    database_path: str = "vibetest.db"
    user_agent: str = "VibeTest/0.1 (authorized security research; university project)"
    request_timeout: float = 15.0
    # Gentle unauthenticated probes (exposed-file checks, later Supabase RLS).
    # Scans only ever run against allowlisted targets; --no-probes disables them.
    enable_probes: bool = True
    # Katana discovery (soft dependency — graceful fallback to single-page fetch).
    katana_bin: str = "katana"
    katana_depth: int = 2
    katana_rate_limit: int = 10          # requests/second — keep gentle
    katana_process_timeout: float = 120.0
    max_pages: int = 20                  # max pages fetched per scan
    # GitHub repo mode (PUBLIC repositories only; static analysis, no live probing).
    github_base: str = "https://github.com"
    # Headless rendering of JavaScript-built pages (optional [crawl] extra).
    # Without Playwright installed the scanner simply keeps the raw HTML.
    render_spa: bool = True
    max_render_pages: int = 5
    render_timeout: float = 20.0
    # OSV.dev dependency-vulnerability lookups (free service, no key).
    # Set to "" to disable external lookups entirely (offline-friendly).
    osv_api_url: str = "https://api.osv.dev/v1/query"
    osv_max_packages: int = 30


def load_settings(path: Path | None = None) -> Settings:
    p = path or DEFAULT_CONFIG_PATH
    if p.exists():
        data = tomllib.loads(p.read_text(encoding="utf-8"))
        return Settings(**data.get("vibetest", data))
    return Settings()
