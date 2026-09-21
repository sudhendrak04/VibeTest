# VibeTest — Implementation Progress

**What this file is:** a plain-language record of everything implemented in the project,
written so it can be read directly to a project guide / professor. It is **updated after
every coding session** (standing rule in `AGENTS.md`).

*Last updated: 2026-09-21 — session 16 (harness now grades all five fixtures).*

---

## 1. What VibeTest is

An automated security scanner for **"vibe-coded" web apps** — apps built quickly with AI
assistants and deployed on free hosting (Vercel, Netlify, Render…). It checks a website
for common security mistakes, and reports them in plain English to a **non-expert owner**.

**Two ground rules enforced by the tool itself:**
1. It only ever scans **targets the owner has authorized** (an allowlist "consent gate"
   refuses everything else, hard).
2. All checks are **read-only and gentle** — no exploitation, no data modification.

## 2. How one scan works (end to end)

1. **Permission check** — the target must be on the allowlist, or the scan is refused
   before any request is made.
2. **URL discovery (Katana)** — a free external crawler tool finds the site's pages
   (if it isn't installed, the tool gracefully falls back to the entry page).
3. **Collection** — the tool fetches the pages, downloads the site's own JavaScript
   files, and records everything into one structured "observation notebook" (the
   `Artifact` object).
4. **Detection** — a set of independent "detector" checks each examine the notebook and
   write standardized "problem cards" (the `Finding` object): what's wrong, where,
   how severe, how to fix it.
5. **Tidy-up** — duplicates removed, findings sorted by severity.
6. **Report** — a self-contained HTML report (with plain-English explanations) is
   generated; the scan is also saved to a small local database.

## 3. Implemented components

### 3.1 Core engine (`vibetest/core/`)

| Component | What it does (simple words) | Status |
|---|---|---|
| Consent gate | The "bouncer": refuses any target not on the allowlist; every request re-checks with it | ✅ |
| Orchestrator | Runs the 6-step pipeline; testable because fetching can be swapped for fake data | ✅ |
| Schemas (contracts) | The two frozen data shapes: `Artifact` (observations) and `Finding` (problem cards) | ✅ |
| Store | Saves every scan + findings to a local SQLite database (re-read old scans without rescanning) | ✅ |
| HTTP helpers | Shared safety patterns: bounded reads (never download huge files) and SPA-fallback detection | ✅ |

### 3.2 Discovery & collection (`vibetest/acquisition/`)

| Component | What it does | Status |
|---|---|---|
| Katana integration | First unit: free crawler tool finds all URLs; runs crawl-only, rate-limited, scoped to the exact host; **soft dependency** (falls back if not installed) | ✅ |
| Crawler | Fetches pages with a plain HTTP client; builds the Artifact | ✅ |
| JS bundle extraction | Finds `<script src>` tags, downloads the app's **own** JavaScript (max 2 MB each; CDN libraries skipped — they're not the app's code), captures `sourceMappingURL` references for later | ✅ |
| Technology recognition | Reads response headers, page HTML, and JS bundles to recognize the framework (Next.js, Nuxt, SvelteKit…), the hosting platform (Vercel, Netlify…), and backend services (Supabase, Firebase, Stripe, Sentry…) — no extra requests | ✅ |
| GitHub repo mode | Downloads a PUBLIC repo archive (github.com only), extracts it safely (path-traversal-safe, size-capped), and maps source files into the Artifact — static analysis, no requests to any deployed site | ✅ |
| SPA rendering (Playwright) | Renders JavaScript-built pages headlessly when installed (optional `[crawl]` extra): the rendered DOM + observed script requests feed bundle extraction, so dynamically injected scripts are finally visible; every browser request is consent-gated; images/fonts/media skipped; graceful raw-HTML fallback when not installed | ✅ |

### 3.3 Detectors — the actual security checks (`vibetest/detectors/`)

| Detector | Checks for | How it works | Severities | Status |
|---|---|---|---|---|
| `headers` | Missing security headers (CSP, HSTS, X-Frame-Options, …) | Examines responses (passive) | INFO–MEDIUM | ✅ |
| `exposed_files` | `.env` files, `.git/` repo leaks, SQL dumps, `config.json`, `.DS_Store` | 11 gentle GET probes; **content-signature validated** so SPA hosts don't cause false alarms; secret values redacted | LOW–CRITICAL | ✅ |
| `secrets_bundle` | Leaked API keys inside the site's JavaScript | 10 specific key signatures (AWS, Stripe, GitHub, OpenAI…) **plus** decoding Supabase JWTs to distinguish the safe `anon` key from the deadly `service_role` key; evidence **masked** | LOW–CRITICAL | ✅ |
| `deps_osv` | Outdated dependencies with known vulnerabilities | Parses exposed manifests (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `package.json`), then queries the **free OSV.dev database** (no key needed); reports CVE/GHSA advisory ids | LOW–CRITICAL | ✅ |
| `supabase_rls` | Database readable without a session — the real **CVE-2025-48757** pattern | Finds the Supabase address + public anon key in the bundles, then reads (never writes) one row per table via the REST API; empty/blocked results are NOT reported (precision-first) | CRITICAL | ✅ |
| `source_maps` | Publicly accessible JavaScript source maps (leak original source code) | Follows `sourceMappingURL` references (and the `.js.map` convention) with bounded reads; validates real source-map content | LOW | ✅ |
| `debug_config` | Development/debug build markers shipped to production (`NODE_ENV=development`, React dev build) | Scans pages and bundles for two high-confidence markers | MEDIUM | ✅ |
| `firebase_rules` | Open Firebase Realtime Database rules (nothing protects the database) | Finds the database URL in the bundles, then reads only the database root once (`/.json`); data returned = CRITICAL, empty-but-public = MEDIUM, denied = not reported | MEDIUM–CRITICAL | ✅ |
| `repo_sensitive_files` | Sensitive files committed to a repository (`.env`, service-account keys, SSH keys, credentials, `.npmrc`) | Repo-mode only: filename checks on repository files; env values masked in evidence | MEDIUM–CRITICAL | ✅ |
| `repo_deps` | Vulnerable dependencies from committed lockfiles | Repo-mode only: parses the repository's own lockfiles and asks the free OSV.dev service | HIGH–CRITICAL | ✅ |

### 3.4 Reporting (`vibetest/reporting/`, `vibetest/cli.py`)

| Component | What it does | Status |
|---|---|---|
| Explanation layer | Plain-English "what this means / why it matters / what to do" text: deterministic templates by default, or a **local Ollama model** (`--llm`; temperature 0, JSON output, per-finding cache, automatic template fallback on any failure) | ✅ template + local LLM |
| HTML report | Self-contained, severity-colored report with evidence; can be shown to non-experts | ✅ |
| CLI | `vibetest scan <url>`, `vibetest scan-repo <owner/name>`, `vibetest targets`, `vibetest serve`; `--no-probes` = passive-only mode · `--no-render` = skip headless rendering | ✅ |
| Evaluation harness | Starts ALL owned demo targets (5 — URL, repo and SPA modes), scans them end-to-end, compares findings with the planted ground-truth labels, and writes category-level precision/recall (`eval/results.md`) with precision guardrails; skips render-dependent targets with a note when Playwright is absent | ✅ |
| Dashboard (web UI) | Polished scan launcher + results viewer (FastAPI + Jinja2): overview stats, severity distribution bars, paste-a-URL scan with live progress panel, per-scan details with styled finding cards, detected technology, one-click full report, JSON API. Scans go through the **same consent gate** as the CLI (non-allowlisted URLs refused); one scan at a time | ✅ |

### 3.5 Safety & ethics features (built-in, not afterthoughts)

- **Consent gate** — unauthorized targets are refused before any network request.
- **Read-only by design** — the tool never writes, modifies, or exploits anything.
- **Gentle probes** — rate-limited, bounded downloads, one row per database table max.
- **Evidence redaction** — leaked secrets and database row values never appear in reports
  (verified by automated checks).
- **Soft dependencies** — missing Katana or offline OSV → the tool degrades gracefully
  instead of crashing.
- **Gated dashboard scans** — the web UI can start scans, but only through the same
  consent gate as the CLI: non-allowlisted URLs are refused before any network
  request, and only one scan runs at a time.
- **Browser traffic is gated too** — headless rendering aborts any request outside
  the allowlist, so the consent gate governs the browser exactly like the crawler.

## 4. Owned demo targets (`targets/`)

Deliberately vulnerable **fake** fixtures owned by the team (legal, safe, reproducible):

| Fixture | Simulates | Planted issues |
|---|---|---|
| `targets/demo_site/` | A vibe-coded static app | Public `.env`; JS bundle with fake `service_role` JWT, `sb_secret_` key, AWS key; exposed `package-lock.json` with outdated packages; public source map; `NODE_ENV=development` marker |
| `targets/demo_supabase/` | A mock Supabase backend (RLS misconfiguration) | `users` table readable without a session; `profiles` table correctly protected (good control case) |
| `targets/demo_firebase/` | A mock Firebase backend (open database rules) | `/.json` returns data without credentials; `firebase_rules` reports CRITICAL |
| `targets/demo_repo/` | A mock GitHub repository (repo-scan mode, served by `tools/mock_github.py`) | Committed `.env` + `serviceAccountKey.json`; fake secrets in `src/app.js`; dev-build marker; outdated lockfile deps |
| `targets/demo_spa/` | A JavaScript-built SPA (rendering demo) | Shell-only HTML; the JavaScript-injected `/static/app.js` carries the fake secrets — visible only with headless rendering |

## 5. Evidence: tests and live demos

- **111 automated tests, all passing** (`pytest`) — no real network used in tests
  (fake HTTP client records what *would* have been requested).
- **Evaluation harness result (category-level, vs planted ground truth):**
  precision **1.00** · recall **1.00** · F1 **1.00** · **0 constraint violations** ·
  **20 ground-truth categories across all five owned targets** (`eval/results.md`,
  regenerated on every harness run).
- **Live demo results:**
  - Full demo site scan → **15 findings**: 5 CRITICAL (4 leaked secrets/`.env` +
    minimist), 2 more vulnerable dependencies (lodash 6 advisories, axios 24 advisories
    — real data from OSV.dev), a development-build marker, an exposed source map,
    header issues, exposed manifest.
  - Mock Supabase scan → CRITICAL "table readable without a session" finding, while the
    protected table and the public anon key are correctly **not** reported.
  - Mock Firebase scan → CRITICAL "database readable without authentication" finding,
    with only top-level key names in the evidence (no data values).
  - Report and CLI now show the detected technology (demo site → `sentry · supabase`).
  - Dashboard (`vibetest serve`) verified live: scan history with severity badges,
    per-scan details, detected technology, one-click full report, JSON API, 404 handling.
  - Dashboard scan flow verified live: paste URL → background job → progress polling →
    findings appear; a non-allowlisted URL is refused with HTTP 403 and a clear message.
  - Dashboard UI verified live: overview stats, proportional severity bars, styled
    finding cards, progress panel, report button.
  - Repo mode verified live (`scan-repo` against the mock GitHub archive) → 9 findings:
    committed `.env` + service-account key, 3 leaked secrets, dev-build marker, and
    lodash/minimist/axios advisories via OSV.dev — zero requests to any deployed site.
  - SPA rendering verified live: the shell-only scan (`--no-render`) found **5 findings**;
    with rendering the same scan found **9** — the JavaScript-injected bundle exposed
    3 CRITICAL leaked secrets that were completely invisible without a browser.
  - LLM mode (`--llm`) verified against **real local Ollama** (qwen2.5:3b): all 6
    findings explained by the model (cache: 6 entries); a second scan with the warm
    cache took **1.9 s** (vs ~3 min cold). Without Ollama, it falls back to templates.
- **Two real bugs caught by tests/demos before shipping:** a `.git/HEAD` pattern error,
  and a too-small download limit that silently dropped large vulnerability responses.

## 6. Not implemented yet (planned next)

- Firestore rule checks (Realtime Database rules are done; Firestore needs collection-name discovery) and client-side-only authorization hints

## 7. Session log

| # | When | What was added |
|---|---|---|
| 1 | 2026-09-12 | Project foundation: contracts, consent gate, orchestrator, store, `headers` detector, HTML report, CLI, first tests and demo |
| 2 | 2026-09-14 | Katana URL-discovery integration (soft dependency); `exposed_files` detector |
| 3 | 2026-09-16 | JS bundle extraction; `secrets_bundle` detector with Supabase JWT role decoding |
| 4 | 2026-09 (recent) | Flagship `supabase_rls` detector; owned demo fixtures committed to `targets/` |
| 5 | 2026-09-20 | `deps_osv` detector (free OSV.dev lookups); shared HTTP helper refactor; fixed OSV truncation bug; this file created |
| 6 | 2026-09-20 | Technology fingerprinter (framework/hosting/backend recognition from headers, HTML, bundles); report + CLI show "Detected technology"; 6 new tests |
| 7 | 2026-09-20 | `source_maps` and `debug_config` detectors; demo fixture gained a source map + dev-build marker; 10 new tests |
| 8 | 2026-09-20 | `firebase_rules` detector (open Realtime Database rules); mock Firebase demo target; 7 new tests |
| 9 | 2026-09-20 | Evaluation harness (`eval/harness.py`) + ground-truth `eval/targets.yaml` + paper-ready `eval/results.md`; 5 new tests |
| 10 | 2026-09-20 | Local dashboard (FastAPI + Jinja2, read-only): scan history, scan details, report view, JSON API; `vibetest serve`; 5 new tests |
| 11 | 2026-09-20 | Local-LLM explanations (`--llm`): Ollama integration, JSON structured output, per-finding cache, automatic template fallback; mock-Ollama dev tool; 7 new tests |
| 12 | 2026-09-20 | Scan-from-dashboard: URL form, background job + progress polling, single-flight, 403 refusal for non-allowlisted URLs; 5 new tests |
| 13 | 2026-09-20 | Dashboard UI overhaul: overview stats, severity distribution bars, styled finding cards, progress panel, polished layout; 1 new test |
| 14 | 2026-09-20 | GitHub repo scan mode (`scan-repo`): safe public-archive download, source-file mapping, `repo_sensitive_files` + `repo_deps` detectors; mock GitHub dev tool + demo repo fixture; 11 new tests |
| 15 | 2026-09-20 | Playwright SPA rendering (optional `[crawl]` extra): SPA detection, headless rendering with consent-gated browser traffic, dynamic-script discovery; SPA demo fixture; 9 new tests |
| 16 | 2026-09-21 | Eval harness extended to all 5 fixtures: repo-mode dispatch, render-dependent skip, flexible fixture readiness URL; `demo_spa` + `demo_repo` ground-truth labels; results regenerated (20 categories, P=R=F1=1.00, 0 violations); 2 new tests |
