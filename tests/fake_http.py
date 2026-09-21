"""Shared duck-typed fakes for httpx.Client, used by acquisition/detector tests.

No network is ever touched: responses are looked up from a dict, and every URL
asked for is recorded in `calls` (so tests can prove the consent gate prevented
a request). Headers sent with each request are recorded in `seen_headers`.
"""
from __future__ import annotations


class FakeStreamResponse:
    def __init__(self, status_code: int = 200, headers: dict | None = None, body: bytes = b""):
        self.status_code = status_code
        self.headers = headers or {}
        self._body = body

    def iter_bytes(self):
        yield self._body


class _FakeStream:
    def __init__(self, response: FakeStreamResponse):
        self._response = response

    def __enter__(self):
        return self._response

    def __exit__(self, *exc):
        return False


class FakeClient:
    """Duck-typed stand-in for httpx.Client; records URLs and headers."""

    def __init__(self, responses: dict[str, FakeStreamResponse] | None = None):
        self.responses = responses or {}
        self.calls: list[str] = []
        self.seen_headers: list[dict] = []
        self.seen_json: list[dict | None] = []

    def stream(self, method: str, url: str, headers: dict | None = None, json: dict | None = None):
        self.calls.append(url)
        self.seen_headers.append(headers or {})
        self.seen_json.append(json)
        return _FakeStream(self.responses.get(url, FakeStreamResponse(404)))
