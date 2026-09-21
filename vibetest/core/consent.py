"""The consent gate. EVERY request to a target passes through here — no exceptions
(AGENTS.md hard constraint #2). The scanner hard-refuses anything not on the allowlist.
"""
from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse


class ConsentDenied(PermissionError):
    """Raised when a scan/probe targets something not on the allowlist."""


class ConsentGate:
    def __init__(self, allowed: Iterable[str]):
        self.allowed = {a.strip().lower() for a in allowed if a and a.strip()}

    def is_allowed(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        # exact match or subdomain of an allowed entry (e.g. app.our-site.vercel.app)
        return any(host == entry or host.endswith("." + entry) for entry in self.allowed)

    def check(self, url: str) -> None:
        if not self.is_allowed(url):
            raise ConsentDenied(
                f"Target not on the allowlist: {url!r}. "
                "Add it to vibetest.toml (allowed_targets) or pass --allow <host>. "
                "Owned/authorized targets only — see PENDING.md legal note."
            )
