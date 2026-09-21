"""Shared JWT helpers for detectors.

Supabase hands out its keys as JWTs whose `role` claim decides what they can do:
`anon` (public by design — safe to ship to the browser) vs `service_role`
(bypasses Row Level Security entirely). Comparing the raw strings cannot tell
them apart — detectors must decode the claim.
"""
from __future__ import annotations

import base64
import binascii
import json
import re

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def jwt_role(token: str) -> str | None:
    """Decode a JWT's payload and return its `role` claim (if any)."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, binascii.Error):
        return None
    if isinstance(payload, dict) and payload.get("role"):
        return str(payload["role"])
    return None
