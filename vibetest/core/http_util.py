"""Shared HTTP response helpers for acquisition and detectors.

One implementation of the two patterns every probe-based check needs:
bounded reads (never download more than N bytes of somebody's file) and
SPA-fallback detection (Vercel/Netlify answer 200 + the app shell for
*every* unknown path — a bare status-code check would flag everything).
"""
from __future__ import annotations


def read_bounded(resp, limit: int) -> bytes:
    """Read at most `limit` bytes from a streaming httpx response."""
    chunks: list[bytes] = []
    size = 0
    for chunk in resp.iter_bytes():
        chunks.append(chunk)
        size += len(chunk)
        if size >= limit:
            break
    return b"".join(chunks)[:limit]


def looks_like_html(content_type: str, raw: bytes) -> bool:
    """True when a response is an HTML page (e.g. an SPA fallback shell)."""
    if "text/html" in content_type.lower():
        return True
    sniff = raw[:200].lstrip().lower()
    return sniff.startswith(b"<!doctype") or sniff.startswith(b"<html")
