"""Mock Supabase REST backend — an OWNED, intentionally-vulnerable demo target.

Emulates just enough of Supabase's PostgREST API to exercise the `supabase_rls`
detector locally (no real `*.supabase.co` host is ever touched):

- `/rest/v1/`          → OpenAPI-style JSON listing the tables (`users`, `profiles`)
- `/rest/v1/users`     → returns rows  → simulates RLS disabled/permissive (BAD)
- `/rest/v1/profiles`  → returns []    → simulates RLS working (GOOD)
- `/` and `/app.js`    → a tiny page + bundle containing a PUBLIC anon key
                         (safe by design — must NOT be flagged as a secret)

Everything here is FAKE. Local demo use only; binds to 127.0.0.1.
Usage:  python targets/demo_supabase/mock_server.py   (port 8127)
"""
from __future__ import annotations

import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

PORT = 8127


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


ANON_JWT = f"{_b64url({'alg': 'HS256', 'typ': 'JWT'})}.{_b64url({'role': 'anon', 'iss': 'supabase'})}.fit_sig"

INDEX_HTML = (
    "<html><head><title>Mock Supabase demo</title></head>"
    '<body><h1>Vibe-coded demo app</h1><script src="/app.js"></script></body></html>'
)

APP_JS = (
    "// Mock demo bundle - PUBLIC anon key (safe by design)\n"
    f'const SUPABASE_URL = "http://127.0.0.1:{PORT}";\n'
    f'const SUPABASE_ANON_KEY = "{ANON_JWT}";\n'
)

OPENAPI_SPEC = {"swagger": "2.0", "paths": {"/users": {}, "/profiles": {}}}

USERS_ROWS = [
    {"id": 1, "email": "demo-user@example.com", "phone": "+1-555-0100"},
    {"id": 2, "email": "second-user@example.com", "phone": "+1-555-0101"},
]


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, status: int = 200) -> None:
        self._send(json.dumps(obj).encode(), "application/json", status)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path
        if path == "/":
            self._send(INDEX_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send(APP_JS.encode(), "application/javascript; charset=utf-8")
        elif path.rstrip("/") == "/rest/v1":
            self._json(OPENAPI_SPEC)
        elif path == "/rest/v1/users":
            self._json(USERS_ROWS)  # intentionally exposed (RLS "off")
        elif path == "/rest/v1/profiles":
            self._json([])  # RLS working — nothing to report
        else:
            self._json({"message": "not found"}, 404)

    def log_message(self, *args) -> None:  # keep the demo console quiet
        pass


if __name__ == "__main__":
    print(f"Mock Supabase target on http://127.0.0.1:{PORT}/ (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
