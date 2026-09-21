"""Explanation layer: turns confirmed findings into plain-English text.

Two modes:
- "template": deterministic, offline, zero dependencies — the always-available default.
- "ollama":   a LOCAL open-weight model via Ollama (temperature 0, JSON-schema
              structured output, per-finding cache). Any failure — Ollama not
              running, model not installed, unparseable output, timeout — falls
              back to template text for the affected findings. A scan is never
              failed by the LLM.

The LLM only ever writes explanations. It never touches detection
(PROJECTS.md §3): the deterministic core stays reproducible.
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Literal

import httpx

from ..config import Settings
from ..schemas.findings import Finding

logger = logging.getLogger(__name__)

Mode = Literal["template", "ollama"]

_SYSTEM_PROMPT = (
    "You are a friendly security assistant inside a website scanner. "
    "You explain ONE security finding to a non-expert website owner. "
    'Reply with JSON only: {"explanation": "..."} where explanation contains '
    "three short paragraphs: what this means, why it matters, and what to do "
    "first. Use plain everyday English, no markdown, no jargon. Never invent "
    "other issues. Never include secret values in the text."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {"explanation": {"type": "string"}},
    "required": ["explanation"],
}


def apply_explanations(
    findings: list[Finding],
    *,
    mode: Mode = "template",
    settings: Settings | None = None,
    client: httpx.Client | None = None,
) -> list[Finding]:
    """Fill `explanation` for findings that don't have one yet."""
    if mode == "ollama":
        _apply_ollama(findings, settings or Settings(), client)
    else:
        _apply_templates(findings)
    return findings


def _template_text(f: Finding) -> str:
    refs = ", ".join(x for x in (f.cwe_id, f.owasp_2025) if x) or "a known weakness type"
    return (
        f"{f.title}.\n\n"
        f"What this means: our scanner found this issue in {len(f.evidence)} place(s) "
        f"on the target; the exact spots are listed in the evidence section.\n\n"
        f"Why it matters: this maps to {refs} and is rated "
        f"{f.severity.value.upper()} severity.\n\n"
        f"What to do: {f.remediation_hint}"
    )


def _apply_templates(findings: list[Finding]) -> None:
    for f in findings:
        if not f.explanation:
            f.explanation = _template_text(f)


# --------------------------------------------------------------- LLM (Ollama)

def _cache_key(model: str, f: Finding) -> str:
    blob = "|".join(
        [
            model,
            f.detector_id,
            f.category,
            f.title,
            f.severity.value,
            f.cwe_id or "",
            f.owasp_2025 or "",
        ]
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _load_cache(path: str) -> dict[str, str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, str)}


def _save_cache(path: str, cache: dict[str, str]) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        logger.warning("could not write LLM cache %s: %s", path, exc)


def _pick_model(client: httpx.Client, settings: Settings) -> str | None:
    """Return the first configured model that Ollama actually has installed."""
    try:
        resp = client.get(settings.ollama_api_url.rstrip("/") + "/api/tags")
        resp.raise_for_status()
        names = {m.get("name", "") for m in resp.json().get("models", [])}
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.warning(
            "Ollama not reachable at %s (%s) — using template explanations",
            settings.ollama_api_url,
            exc,
        )
        return None
    for candidate in (settings.ollama_model, settings.ollama_fallback_model):
        if candidate in names or f"{candidate}:latest" in names:
            return candidate
    logger.warning(
        "no configured Ollama model installed (tried %s, %s) — using templates",
        settings.ollama_model,
        settings.ollama_fallback_model,
    )
    return None


def _finding_prompt(f: Finding) -> str:
    lines = [
        f"Title: {f.title}",
        f"Category: {f.category}",
        f"Severity: {f.severity.value}",
    ]
    if f.cwe_id:
        lines.append(f"CWE: {f.cwe_id}")
    if f.owasp_2025:
        lines.append(f"OWASP Top 10 (2025): {f.owasp_2025}")
    lines.append(f"Evidence: {len(f.evidence)} location(s) on the site")
    if f.evidence and f.evidence[0].detail:
        lines.append(f"First location detail: {f.evidence[0].detail}")
    if f.remediation_hint:
        lines.append(f"Suggested fix: {f.remediation_hint}")
    return "\n".join(lines)


def _llm_explain(client: httpx.Client, settings: Settings, model: str, f: Finding) -> str:
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _finding_prompt(f)},
        ],
        "stream": False,
        "format": _RESPONSE_SCHEMA,
        "options": {"temperature": 0, "seed": 0},
    }
    resp = client.post(settings.ollama_api_url.rstrip("/") + "/api/chat", json=payload)
    resp.raise_for_status()
    content = resp.json()["message"]["content"]
    explanation = json.loads(content)["explanation"].strip()
    if not explanation:
        raise ValueError("empty explanation from model")
    return explanation


def _cached_explanation(cache: dict[str, str], models: list[str], f: Finding) -> str | None:
    for model in models:
        hit = cache.get(_cache_key(model, f))
        if hit:
            return hit
    return None


def _apply_ollama(findings: list[Finding], settings: Settings, client: httpx.Client | None) -> None:
    cache = _load_cache(settings.llm_cache_path)
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=settings.ollama_timeout)
    try:
        model = _pick_model(client, settings)
        candidates = list(
            dict.fromkeys(
                [m for m in (model, settings.ollama_model, settings.ollama_fallback_model) if m]
            )
        )
        for f in findings:
            if f.explanation:
                continue

            # Serve from cache first — a pre-warmed cache makes demos fully offline.
            cached = _cached_explanation(cache, candidates, f)
            if cached is not None:
                f.explanation = cached
                continue

            if model is None:
                f.explanation = _template_text(f)
                continue

            try:
                text = _llm_explain(client, settings, model, f)
            except Exception as exc:  # noqa: BLE001 — a scan must never fail because of the LLM
                logger.warning("LLM explanation failed for %r (%s) — using template", f.title, exc)
                f.explanation = _template_text(f)
                continue

            cache[_cache_key(model, f)] = text
            _save_cache(settings.llm_cache_path, cache)  # write-through: keep progress
            f.explanation = text
    finally:
        if own_client:
            client.close()
