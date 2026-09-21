"""Mock GitHub archive server (test double for repo-mode demos).

Serves `/{owner}/{repo}/archive/refs/heads/{branch}.tar.gz` built from a local
directory (default: targets/demo_repo), so `vibetest scan-repo` can be demoed
end-to-end without touching the real github.com.

Usage:  python tools/mock_github.py [port] [source_dir]   (default 8130)
"""
from __future__ import annotations

import io
import re
import sys
import tarfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_PORT = 8130
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = ROOT / "targets" / "demo_repo"
ARCHIVE_RE = re.compile(r"^/([^/]+)/([^/]+)/archive/refs/heads/([^/]+)\.tar\.gz$")


def _build_tarball(source: Path, top: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path in sorted(p for p in source.rglob("*") if p.is_file()):
            rel = path.relative_to(source).as_posix()
            tf.add(path, arcname=f"{top}/{rel}")
    return buf.getvalue()


class Handler(BaseHTTPRequestHandler):
    source = DEFAULT_SOURCE

    def _send(self, body: bytes, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/gzip")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        match = ARCHIVE_RE.match(urlsplit(self.path).path)
        if not match:
            self._send(b"not found", 404)
            return
        _owner, repo, branch = match.groups()
        self._send(_build_tarball(self.source, f"{repo}-{branch}"))

    def log_message(self, *args) -> None:  # keep the demo console quiet
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    if len(sys.argv) > 2:
        Handler.source = Path(sys.argv[2]).resolve()
    print(f"Mock GitHub on http://127.0.0.1:{port}/ (serving {Handler.source})")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
