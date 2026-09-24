"""PDF export via Playwright's headless Chromium (soft dependency).

Reuses the already-installed `[crawl]` extra — no separate PDF engine needed
(unlike WeasyPrint, which requires a GTK runtime on Windows). When Playwright
is unavailable, callers surface a clear error and the dashboard falls back to
the browser's own Print-to-PDF flow.
"""
from __future__ import annotations

import logging
import re
from importlib import util as importlib_util

logger = logging.getLogger(__name__)

# <details> without an `open` attribute (collapsible evidence sections) — the
# PDF must contain them expanded, otherwise the printed report hides evidence.
_DETAILS_RE = re.compile(r"<details(?![^>]*\bopen\b)", re.IGNORECASE)

_PRINT_CSS = """
<style>
  @page { size: A4; margin: 14mm; }
  body { max-width: none; margin: 0; }
  .finding { break-inside: avoid; page-break-inside: avoid; }
  * { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
</style>
"""


def expand_details(html: str) -> str:
    """Open every <details> so collapsible content (evidence) appears in the PDF."""
    return _DETAILS_RE.sub("<details open", html)


def is_available() -> bool:
    """True when the playwright package is importable (browser binary checked at launch)."""
    return importlib_util.find_spec("playwright") is not None


def render_pdf(html: str) -> bytes:
    """Render a self-contained HTML report to PDF bytes.

    Collapsible sections (evidence) are expanded first so the PDF contains the
    full report. Raises RuntimeError with a clear message when Playwright (or
    its browser) is not available, and on any rendering failure.
    """
    if not is_available():
        raise RuntimeError(
            'PDF export needs the optional crawl extra: pip install -e ".[crawl]" '
            "then playwright install chromium"
        )
    from playwright.sync_api import sync_playwright

    html = expand_details(html)
    if "</head>" in html:
        html = html.replace("</head>", _PRINT_CSS + "</head>", 1)
    else:
        html += _PRINT_CSS

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_content(html, wait_until="load")
            pdf = page.pdf(format="A4", print_background=True)
            browser.close()
    except Exception as exc:  # noqa: BLE001 — surface one clean message to callers
        raise RuntimeError(f"PDF rendering failed: {exc}") from exc
    return pdf
