"""Technology fingerprinting — what is this site built with? (Week 5)

Works only on data we already collected (response headers, page HTML, JS bundle
contents) — it makes NO extra requests. Feeds:
- the report/CLI ("Detected technology: Sentry · Supabase"),
- detectors that benefit from knowing the stack (e.g. future Firebase checks).
"""
from __future__ import annotations

from ..schemas.artifacts import JSBundle, PageSnapshot, TechFingerprint

# header presence -> hosting platform
_HOSTING_BY_HEADER = (
    ("x-vercel-id", "vercel"),
    ("x-vercel-cache", "vercel"),
    ("x-nf-request-id", "netlify"),
    ("x-render-origin-server", "render"),
    ("cf-ray", "cloudflare"),
)

# x-powered-by value -> framework
_FRAMEWORK_BY_POWERED_BY = (
    ("next.js", "next.js"),
    ("express", "express"),
    ("php", "php"),
)

# lowercase substring in page HTML -> framework
_FRAMEWORK_HTML_MARKERS = (
    ("__next_data__", "next.js"),
    ("/_next/", "next.js"),
    ("__nuxt__", "nuxt"),
    ("/_nuxt/", "nuxt"),
    ("data-sveltekit", "sveltekit"),
    ("/_app/immutable/", "sveltekit"),
    ("data-astro-", "astro"),
    ("astro-island", "astro"),
    ("ng-version", "angular"),
    ("__vue__", "vue"),
)

# lowercase substrings (HTML or bundles) -> backend service
_SERVICE_MARKERS = (
    ("supabase", ("supabase.co",)),
    ("firebase", (
        "firebaseio.com",
        "firebaseapp.com",
        "firestore.googleapis.com",
        "firebaseinstallations.googleapis.com",
    )),
    ("clerk", ("clerk.accounts.dev", "clerk.com", "@clerk/")),
    ("auth0", ("auth0.com", "@auth0/")),
    ("stripe", ("js.stripe.com",)),
    ("sentry", ("sentry.io", "@sentry/", "sentry.init")),
)


def _lower_headers(page: PageSnapshot) -> dict[str, str]:
    return {k.lower(): v for k, v in page.headers.items()}


def _detect_hosting(pages: list[PageSnapshot]) -> str | None:
    for page in pages:
        headers = _lower_headers(page)
        for key, hosting in _HOSTING_BY_HEADER:
            if key in headers:
                return hosting
        server = headers.get("server", "").lower()
        if "netlify" in server:
            return "netlify"
        if "github" in server:
            return "github-pages"
        if "render" in server:
            return "render"
    return None


def _detect_framework(pages: list[PageSnapshot]) -> str | None:
    for page in pages:
        powered_by = _lower_headers(page).get("x-powered-by", "").lower()
        for needle, framework in _FRAMEWORK_BY_POWERED_BY:
            if needle in powered_by:
                return framework
    for page in pages:
        html = page.html.lower()
        for marker, framework in _FRAMEWORK_HTML_MARKERS:
            if marker in html:
                return framework
    return None


def _detect_services(haystacks: list[str]) -> list[str]:
    found: set[str] = set()
    for hay in haystacks:
        for name, markers in _SERVICE_MARKERS:
            if any(marker in hay for marker in markers):
                found.add(name)
    return sorted(found)


def detect(pages: list[PageSnapshot], bundles: list[JSBundle]) -> TechFingerprint:
    """Recognize framework, hosting platform, and backend services. No network."""
    haystacks = [p.html.lower() for p in pages] + [b.content.lower() for b in bundles]
    return TechFingerprint(
        framework=_detect_framework(pages),
        hosting=_detect_hosting(pages),
        backend_services=_detect_services(haystacks),
    )
