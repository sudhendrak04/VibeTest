"""Mock Ollama server (TEST DOUBLE — not a real model).

Serves just enough of the Ollama HTTP API to exercise the scanner's LLM
explanation layer end-to-end WITHOUT downloading a multi-GB local model:

- GET  /api/tags  → lists the configured model names
- POST /api/chat  → returns the structured JSON shape Ollama returns, with a
                    canned explanation that includes the finding's title

Use this for development and pipeline demos. For real explanations, install
Ollama (https://ollama.com), pull a model (e.g. `ollama pull qwen3:8b`), and
run the scanner with `--llm` instead of starting this script.

Usage:  python tools/mock_ollama.py [port]   (default 11434, localhost only)
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

DEFAULT_PORT = 11434
MODEL_NAMES = ["qwen3:8b", "phi4-mini"]


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        if urlsplit(self.path).path == "/api/tags":
            self._send_json({"models": [{"name": n, "model": n} for n in MODEL_NAMES]})
        else:
            self._send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802 (stdlib naming)
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        if urlsplit(self.path).path != "/api/chat":
            self._send_json({"error": "not found"}, 404)
            return
        try:
            payload = json.loads(raw)
            user_msg = payload["messages"][-1]["content"]
            model = payload.get("model", "mock")
        except (ValueError, KeyError, IndexError):
            user_msg, model = "unknown finding", "mock"
        title_line = next(
            (line for line in user_msg.splitlines() if line.startswith("Title:")),
            "Title: a security issue",
        )
        title = title_line.removeprefix("Title:").strip()
        explanation = (
            f"(mock local model) {title} — this is a small but important safety detail "
            "on your site. It matters because attackers can use it to reach data or "
            "visitors they should never see. Apply the suggested fix, then rescan to "
            "confirm it is gone."
        )
        self._send_json(
            {
                "model": model,
                "message": {"role": "assistant", "content": json.dumps({"explanation": explanation})},
                "done": True,
            }
        )

    def log_message(self, *args) -> None:  # keep the console quiet
        pass


if __name__ == "__main__":
    import sys

    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    print(f"Mock Ollama on http://127.0.0.1:{port}/ (test double — Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
