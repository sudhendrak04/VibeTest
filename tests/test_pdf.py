"""PDF export tests — hermetic, plus one real-Chromium integration test."""
import pytest

from vibetest.reporting.pdf import expand_details, render_pdf, is_available


def test_render_pdf_raises_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr("vibetest.reporting.pdf.is_available", lambda: False)
    with pytest.raises(RuntimeError, match="playwright"):
        render_pdf("<html><body>hi</body></html>")


def test_expand_details_opens_collapsed_sections():
    html = '<details><summary>Evidence (2)</summary><div class="evidence">x</div></details>'
    out = expand_details(html)
    assert "<details open>" in out
    assert "Evidence (2)" in out


def test_expand_details_keeps_already_open_and_preserves_attributes():
    html = (
        '<details open class="k"><p>a</p></details>'
        '<details class="y" data-x="1"><p>b</p></details>'
    )
    out = expand_details(html)
    assert out.count("<details") == 2
    assert "open open" not in out
    assert '<details open class="y" data-x="1">' in out


@pytest.mark.skipif(not is_available(), reason="playwright not installed")
def test_render_pdf_real_chromium_outputs_valid_pdf():
    html = (
        "<html><head><title>t</title></head><body><h1>Hello</h1>"
        "<details><summary>Evidence (1)</summary><p>frameable-evidence-marker</p></details>"
        "</body></html>"
    )
    out = render_pdf(html)
    assert out.startswith(b"%PDF")
    assert len(out) > 1000
