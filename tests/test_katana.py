"""Katana wrapper + crawler-selection tests. No live binary or network needed."""
import json

from vibetest.acquisition import crawler, katana
from vibetest.config import Settings
from vibetest.core.consent import ConsentGate
from vibetest.core.context import ScanContext

SAMPLE_JSONL = "\n".join(
    [
        json.dumps(
            {
                "request": {"endpoint": "http://localhost:8000/", "method": "GET"},
                "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}},
            }
        ),
        json.dumps(
            {
                "request": {"endpoint": "http://localhost:8000/about", "method": "GET"},
                "response": {"status_code": 200, "headers": {}},
            }
        ),
        json.dumps(
            {
                "request": {"endpoint": "https://evil.example.net/x", "method": "GET"},
                "response": {"status_code": 200, "headers": {}},
            }
        ),
        "this line is not json and must be skipped",
    ]
)


def _ctx(**settings_kwargs) -> ScanContext:
    return ScanContext(
        settings=Settings(**settings_kwargs),
        gate=ConsentGate(["localhost"]),
    )


def test_parse_jsonl_fields_and_noise():
    parsed = katana.parse_jsonl(SAMPLE_JSONL)
    assert [d.url for d in parsed][:2] == ["http://localhost:8000/", "http://localhost:8000/about"]
    assert parsed[0].status_code == 200
    assert parsed[0].headers["content-type"] == "text/html"
    assert len(parsed) == 3  # the junk line was skipped, not fatal


def test_allowed_only_drops_non_allowlisted_hosts():
    kept = katana.allowed_only(katana.parse_jsonl(SAMPLE_JSONL), ConsentGate(["localhost"]))
    assert {d.url for d in kept} == {"http://localhost:8000/", "http://localhost:8000/about"}


def test_discover_returns_empty_when_binary_missing():
    ctx = _ctx(katana_bin="definitely-not-a-real-binary-xyz")
    assert katana.discover("http://localhost:8000/", ctx) == []


def test_select_urls_entry_first_dedupes_and_caps():
    entry = "http://localhost:8000/"
    discovered = [katana.DiscoveredURL(url=entry)] + [
        katana.DiscoveredURL(url=f"http://localhost:8000/p{i}") for i in range(10)
    ]
    assert crawler.select_urls(entry, discovered, max_pages=3) == [
        entry,
        "http://localhost:8000/p0",
        "http://localhost:8000/p1",
    ]
