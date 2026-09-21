"""CONTRACT 1 — the Artifact: everything acquisition observed about a target.

This schema is FROZEN (Week 2). It is the only input detectors may see.
Changes require agreement of all three team members (see AGENTS.md).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pydantic import BaseModel, Field


def _new_id() -> str:
    return uuid4().hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PageSnapshot(BaseModel):
    url: str
    status_code: int
    headers: dict[str, str] = Field(default_factory=dict)  # keys normalized to lowercase
    html: str = ""


class JSBundle(BaseModel):
    url: str
    content: str = ""
    source_map_url: str | None = None


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)


class TechFingerprint(BaseModel):
    framework: str | None = None        # e.g. "next.js", "nuxt", "sveltekit"
    hosting: str | None = None          # e.g. "vercel", "netlify", "render", "github-pages"
    backend_services: list[str] = Field(default_factory=list)  # e.g. ["supabase", "firebase"]


class TLSInfo(BaseModel):
    version: str | None = None
    issuer: str | None = None


class CookieMeta(BaseModel):
    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str | None = None


class Artifact(BaseModel):
    """Everything the crawler observed. The single source of truth for detectors."""

    scan_id: str = Field(default_factory=_new_id)
    target_url: str
    fetched_at: datetime = Field(default_factory=_utcnow)
    pages: list[PageSnapshot] = Field(default_factory=list)
    js_bundles: list[JSBundle] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    tech: TechFingerprint = Field(default_factory=TechFingerprint)
    tls: TLSInfo | None = None
    cookies: list[CookieMeta] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
