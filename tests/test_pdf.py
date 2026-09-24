"""PDF export tests — hermetic, plus one real-Chromium integration test."""
import pytest

from vibetest.reporting import pdf


def test_render_pdf_raises_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr(pdf, "is_available", lambda: False)
    with pytest.raises(RuntimeError, match="playwright"):
        pdf.render_pdf("<html><body>hi</body></html>")


@pytest.mark.skipif(not pdf.is_available(), reason="playwright not installed")
def test_render_pdf_real_chromium_outputs_valid_pdf():
    out = pdf.render_pdf("<html><head><title>t</title></head><body><h1>Hello</h1></body></html>")
    assert out.startswith(b"%PDF")
    assert len(out) > 1000
