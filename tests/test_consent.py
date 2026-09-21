"""Consent gate tests: the bouncer works and cannot be trivially bypassed."""
import pytest

from vibetest.core.consent import ConsentDenied, ConsentGate


def test_allows_exact_and_subdomain():
    gate = ConsentGate(["example.com", "localhost"])
    assert gate.is_allowed("http://example.com/page")
    assert gate.is_allowed("https://app.example.com/")
    assert gate.is_allowed("http://localhost:8000/")


def test_denies_unlisted_and_lookalikes():
    gate = ConsentGate(["example.com"])
    assert not gate.is_allowed("https://evil.com/")
    assert not gate.is_allowed("https://example.com.evil.com/")
    assert not gate.is_allowed("not-a-url")
    with pytest.raises(ConsentDenied):
        gate.check("https://evil.com/")
