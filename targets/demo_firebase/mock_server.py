"""Mock Firebase Realtime Database — an OWNED, intentionally-vulnerable demo target.

Emulates just enough of the Firebase RTDB REST API to exercise the
`firebase_rules` detector locally (no real *.firebaseio.com host is ever touched):

- `/`       → tiny page referencing /app.js
- `/app.js` → bundle containing a public firebaseConfig (databaseURL)
- `/.json`  → returns FAKE data WITHOUT credentials → simulates open Security
              Rules (the vulnerable case)
- anything else → 404

Everything here is FAKE. Local demo use only; binds to 127.0.0.1.
Usage:  python targets/demo_firebase/mock_server.py   (port 8128)
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

PORT = 8128

DATABASE = {
    "users": {"u1": {"email": "demo@example.com"}, "u2": {"email": "second@example.com"}},
    "settings": {"theme": "dark"},
}

INDEX_HTML = (
    "<html><head><title>Mock Firebase demo</title></head>"
    '<body><h1>Vibe-coded demo app</h1><script src="/app.js"></script></body></html>'
)

APP_JS = (
    "// Mock demo bundle - public Firebase config (the URL is public by design)\n"
    f'const firebaseConfig = {{ apiKey: "demo-key", databaseURL: "http://127.0.0.1:{PORT}" }};\n'
    "firebase.initializeApp(firebaseConfig);\n"
)


class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, content_type: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = urlsplit(self.path).path
        if path == "/":
            self._send(INDEX_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/app.js":
            self._send(APP_JS.encode(), "application/javascript; charset=utf-8")
        elif path == "/.json":
            self._send(json.dumps(DATABASE).encode(), "application/json")  # open rules (BAD)
        else:
            self._send(b'{"error":"not found"}', "application/json", 404)

    def log_message(self, *args) -> None:  # keep the demo console quiet
        pass


if __name__ == "__main__":
    print(f"Mock Firebase target on http://127.0.0.1:{PORT}/ (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
