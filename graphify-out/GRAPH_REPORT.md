# Graph Report - .  (2026-09-21)

## Corpus Check
- Corpus is ~46,957 words - fits in a single context window. You may not need a graph.

## Summary
- 709 nodes · 2136 edges · 34 communities (29 shown, 5 thin omitted)
- Extraction: 84% EXTRACTED · 16% INFERRED · 0% AMBIGUOUS · INFERRED: 339 edges (avg confidence: 0.6)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Core scan pipeline & consent gate|Core scan pipeline & consent gate]]
- [[_COMMUNITY_Project docs & demo fixtures|Project docs & demo fixtures]]
- [[_COMMUNITY_Backend database detectors|Backend database detectors]]
- [[_COMMUNITY_Dashboard & web layer|Dashboard & web layer]]
- [[_COMMUNITY_Analysis, orchestration & explanations|Analysis, orchestration & explanations]]
- [[_COMMUNITY_Bundle extraction & evaluation|Bundle extraction & evaluation]]
- [[_COMMUNITY_Crawling & URL discovery|Crawling & URL discovery]]
- [[_COMMUNITY_Fingerprinting & repo acquisition|Fingerprinting & repo acquisition]]
- [[_COMMUNITY_SPA rendering|SPA rendering]]
- [[_COMMUNITY_Detector framework & registry|Detector framework & registry]]
- [[_COMMUNITY_Dependency scanning (OSV)|Dependency scanning (OSV)]]
- [[_COMMUNITY_Mock demo servers|Mock demo servers]]
- [[_COMMUNITY_Contracts & schemas|Contracts & schemas]]
- [[_COMMUNITY_Header security detector|Header security detector]]
- [[_COMMUNITY_Dependency detector tests|Dependency detector tests]]
- [[_COMMUNITY_Debug-config detector tests|Debug-config detector tests]]
- [[_COMMUNITY_HTTP helpers & Firebase rules|HTTP helpers & Firebase rules]]
- [[_COMMUNITY_Exposed-files detector|Exposed-files detector]]
- [[_COMMUNITY_Secrets-bundle tests|Secrets-bundle tests]]
- [[_COMMUNITY_SQLite persistence layer|SQLite persistence layer]]
- [[_COMMUNITY_Dependency manifests|Dependency manifests]]
- [[_COMMUNITY_Detector run interface|Detector run interface]]
- [[_COMMUNITY_Severity  CWE mapping|Severity / CWE mapping]]
- [[_COMMUNITY_Demo SPA bundle (firebase)|Demo SPA bundle (firebase)]]
- [[_COMMUNITY_Demo SPA bundle (supabase)|Demo SPA bundle (supabase)]]
- [[_COMMUNITY_Demo SPA bundle|Demo SPA bundle]]
- [[_COMMUNITY_Package init|Package init]]

## God Nodes (most connected - your core abstractions)
1. `ConsentGate` - 85 edges
2. `ScanContext` - 71 edges
3. `Settings` - 67 edges
4. `Artifact` - 62 edges
5. `BaseDetector` - 55 edges
6. `FakeClient` - 54 edges
7. `PageSnapshot` - 51 edges
8. `FakeStreamResponse` - 42 edges
9. `JSBundle` - 41 edges
10. `Store` - 38 edges

## Surprising Connections (you probably didn't know these)
- `CLAUDE.md — graphify rules` --semantically_similar_to--> `AGENTS.md — Project Guidance`  [INFERRED] [semantically similar]
  CLAUDE.md → AGENTS.md
- `Ground-truth eval targets (targets.yaml)` --references--> `secrets_bundle detector`  [INFERRED]
  eval/targets.yaml → vibetest/detectors/secrets_bundle.py
- `Two-layer checklist philosophy` --conceptually_related_to--> `repo_deps detector`  [INFERRED]
  PROJECTS.md → vibetest/detectors/repo_deps.py
- `Two-layer checklist philosophy` --conceptually_related_to--> `repo_sensitive_files detector`  [INFERRED]
  PROJECTS.md → vibetest/detectors/repo_sensitive_files.py
- `firebase_rules detector` --references--> `JS bundle extraction`  [INFERRED]
  vibetest/detectors/firebase_rules.py → PROGRESS.md

## Import Cycles
- 1-file cycle: `vibetest/schemas/artifacts.py -> vibetest/schemas/artifacts.py`
- 1-file cycle: `vibetest/web/app.py -> vibetest/web/app.py`
- 1-file cycle: `vibetest/detectors/__init__.py -> vibetest/detectors/__init__.py`

## Hyperedges (group relationships)
- **Scan pipeline: consent gate → discovery → detect → explain → report** — agents_consentgate, progress_katana, docs_artifact, docs_finding, progress_explanationlayer, progress_htmlreport [EXTRACTED 1.00]
- **Detector plugin set (one vulnerability class per file)** — progress_headers, progress_exposedfiles, progress_secretsbundle, progress_depsosv, progress_supabase_rls, progress_firebase_rules, progress_source_maps, progress_debug_config, progress_repo_sensitive_files, progress_repo_deps [EXTRACTED 1.00]
- **Owned demo fixture portfolio (Pool 1)** — targets_demo_site, targets_demo_supabase, targets_demo_firebase, targets_demo_spa, targets_demo_repo [EXTRACTED 1.00]

## Communities (34 total, 5 thin omitted)

### Community 0 - "Core scan pipeline & consent gate"
Cohesion: 0.06
Nodes (79): BaseDetector, ConsentGate, ScanContext, Run all enabled detectors. Probe-based detectors only when probes are allowed., run_detectors(), run_scan(), Download a public repository and analyze it statically.      Raises ValueError f, run_repo_scan() (+71 more)

### Community 1 - "Project docs & demo fixtures"
Cohesion: 0.09
Nodes (66): AGENTS.md — Project Guidance, Consent / allowlist gate, graphify knowledge graph, VibeTest, CLAUDE.md — graphify rules, Mock Firebase Realtime Database — an OWNED, intentionally-vulnerable demo target, Mock Supabase REST backend — an OWNED, intentionally-vulnerable demo target.  Em, ARCHITECTURE.md — Architecture & Data Flow (+58 more)

### Community 2 - "Backend database detectors"
Cohesion: 0.08
Nodes (52): FirebaseRulesDetector, jwt_role(), Shared JWT helpers for detectors.  Supabase hands out its keys as JWTs whose `ro, Decode a JWT's payload and return its `role` claim (if any)., SourceMapsDetector, SupabaseRLSDetector, JSBundle, FakeClient (+44 more)

### Community 3 - "Dashboard & web layer"
Cohesion: 0.07
Nodes (49): ConsentDenied, Raised when a scan/probe targets something not on the allowlist., FastAPI, PermissionError, Self-contained HTML report (Jinja2, inline template to avoid package-data config, render_report(), ScanRunner, _poll_job() (+41 more)

### Community 4 - "Analysis, orchestration & explanations"
Cohesion: 0.09
Nodes (39): dedup(), _fingerprint(), Dedup + ordering of findings., sort_by_severity(), The consent gate. EVERY request to a target passes through here — no exceptions, The pipeline runner. Fetcher and probe client are injectable so tests never touc, GitHub-repository scan mode — static analysis of PUBLIC repositories.  Downloads, Mode (+31 more)

### Community 5 - "Bundle extraction & evaluation"
Cohesion: 0.08
Nodes (38): Week 4 — JS bundle extraction from already-fetched pages.  Parses `<script src>`, Collect <script src> values. Malformed HTML is skipped, never fatal., script_srcs(), _ScriptSrcCollector, evaluate(), Compare one scan's findings with its ground-truth spec (pure function)., HTMLParser, PageSnapshot (+30 more)

### Community 6 - "Crawling & URL discovery"
Cohesion: 0.09
Nodes (30): _apply_rendering(), fetch(), Crawler. Katana discovery (soft dependency) + httpx fetching + JS bundle extract, Entry page first, then discovered URLs (deduped, capped). Pure — unit-tested., Render SPA-looking pages when Playwright is installed.      Replaces raw shell H, Discover URLs (Katana), fetch each page, then download the app's JS bundles., select_urls(), extract_bundles() (+22 more)

### Community 7 - "Fingerprinting & repo acquisition"
Cohesion: 0.11
Nodes (25): detect(), _detect_framework(), _detect_hosting(), _detect_services(), _lower_headers(), Technology fingerprinting — what is this site built with? (Week 5)  Works only o, Recognize framework, hosting platform, and backend services. No network., build_repo_artifact() (+17 more)

### Community 8 - "SPA rendering"
Cohesion: 0.12
Nodes (25): is_available(), looks_like_spa(), Headless-browser rendering for JavaScript-built pages (optional [crawl] extra)., True when the playwright package is importable (browser binary is checked at lau, True for sparse JS shells that need rendering to reveal the real page., Browser traffic policy: the consent gate is authoritative., Render each URL headlessly. Returns {} when Playwright is unavailable., render_pages() (+17 more)

### Community 9 - "Detector framework & registry"
Cohesion: 0.16
Nodes (16): ABC, ScanContext: what the orchestrator hands to acquisition and detectors.  Lives in, The detector interface (Builder B's framework).  Every detector: (1) has a name, Layer-2 detector: development/debug build markers shipped to production.  High-c, all_detectors(), enabled(), Plugin registry. One vulnerability class = one file = one registered detector., register() (+8 more)

### Community 10 - "Dependency scanning (OSV)"
Cohesion: 0.14
Nodes (21): _advisory_ids(), _dedupe(), parse_manifest(), _parse_package_json(), _parse_package_lock(), _parse_pnpm_lock(), _parse_yarn_lock(), query_osv() (+13 more)

### Community 11 - "Mock demo servers"
Cohesion: 0.11
Nodes (8): BaseHTTPRequestHandler, Handler, Handler, _build_tarball(), Handler, Path, Handler, Mock Ollama server (TEST DOUBLE — not a real model).  Serves just enough of the

### Community 12 - "Contracts & schemas"
Cohesion: 0.18
Nodes (15): BaseModel, datetime, Artifact, CookieMeta, Endpoint, CONTRACT 1 — the Artifact: everything acquisition observed about a target.  This, Everything the crawler observed. The single source of truth for detectors., TLSInfo (+7 more)

### Community 13 - "Header security detector"
Cohesion: 0.18
Nodes (13): BaseDetector, Layer-1 detector: missing HTTP security headers (passive)., SecurityHeadersDetector, Artifact, Finding, ScanContext, Artifact, Finding (+5 more)

### Community 14 - "Dependency detector tests"
Cohesion: 0.24
Nodes (11): DepsOSVDetector, _artifact(), _ctx(), ScanContext, Vulnerable-dependencies detector tests (fake HTTP client — no network)., Regression: real OSV responses can exceed 200 KB (e.g. axios@0.21.1);     a too-, test_large_osv_response_is_not_truncated(), test_manifest_and_vulnerable_dependency_reported() (+3 more)

### Community 15 - "Debug-config detector tests"
Cohesion: 0.23
Nodes (14): _context(), DebugConfigDetector, Match, _artifact(), _ctx(), ScanContext, Debug/dev build marker detector tests (pure — no network)., test_clean_assets_no_findings() (+6 more)

### Community 16 - "HTTP helpers & Firebase rules"
Cohesion: 0.19
Nodes (9): looks_like_html(), Shared HTTP response helpers for acquisition and detectors.  One implementation, Read at most `limit` bytes from a streaming httpx response., True when a response is an HTML page (e.g. an SPA fallback shell)., read_bounded(), Layer-2 detector: open Firebase Realtime Database Security Rules.  The Firebase, Artifact, Finding (+1 more)

### Community 17 - "Exposed-files detector"
Cohesion: 0.21
Nodes (11): _base_url(), _matches_signature(), ProbeSpec, Layer-1 detector: exposed sensitive files.  Checks a small fixed list of well-kn, Mask secret VALUES in env-style text — keys stay visible, values become ***., Mask secret VALUES in evidence — keys stay visible, values become ***., _redact(), redact_env_values() (+3 more)

### Community 18 - "Secrets-bundle tests"
Cohesion: 0.26
Nodes (12): _b64url(), _jwt(), Secrets-in-bundle detector tests (pure — no network, no client needed)., The anon key is public BY DESIGN — flagging it would be a false positive., _run(), test_anon_jwt_is_not_a_finding(), test_aws_key_detected_and_masked(), test_clean_bundle_has_no_findings() (+4 more)

### Community 19 - "SQLite persistence layer"
Cohesion: 0.27
Nodes (5): FindingRow, SQLite persistence. Scan once, re-render reports without re-scanning., ScanRow, SQLModel, ScanResult

### Community 20 - "Dependency manifests"
Cohesion: 0.25
Nodes (7): dependencies, axios, lodash, minimist, name, private, version

### Community 21 - "Detector run interface"
Cohesion: 0.40
Nodes (4): Inspect the artifact and return findings. Never fetch on your own., Artifact, Finding, ScanContext

## Knowledge Gaps
- **37 isolated node(s):** `name`, `version`, `private`, `axios`, `lodash` (+32 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **5 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ConsentGate` connect `Core scan pipeline & consent gate` to `Backend database detectors`, `Dashboard & web layer`, `Analysis, orchestration & explanations`, `Bundle extraction & evaluation`, `Crawling & URL discovery`, `SPA rendering`, `Detector framework & registry`, `Dependency detector tests`, `Debug-config detector tests`, `Secrets-bundle tests`?**
  _High betweenness centrality (0.084) - this node is a cross-community bridge._
- **Why does `BaseDetector` connect `Header security detector` to `Core scan pipeline & consent gate`, `Backend database detectors`, `Detector framework & registry`, `Dependency scanning (OSV)`, `Dependency detector tests`, `Debug-config detector tests`, `HTTP helpers & Firebase rules`, `Exposed-files detector`, `Detector run interface`?**
  _High betweenness centrality (0.083) - this node is a cross-community bridge._
- **Why does `Artifact` connect `Contracts & schemas` to `Core scan pipeline & consent gate`, `Backend database detectors`, `Dashboard & web layer`, `Analysis, orchestration & explanations`, `Bundle extraction & evaluation`, `Crawling & URL discovery`, `Fingerprinting & repo acquisition`, `Detector framework & registry`, `Dependency scanning (OSV)`, `Header security detector`, `Dependency detector tests`, `Debug-config detector tests`, `HTTP helpers & Firebase rules`, `Exposed-files detector`, `Secrets-bundle tests`?**
  _High betweenness centrality (0.071) - this node is a cross-community bridge._
- **Are the 32 inferred relationships involving `ConsentGate` (e.g. with `ScanContext` and `ConsentGate`) actually correct?**
  _`ConsentGate` has 32 INFERRED edges - model-reasoned connections that need verification._
- **Are the 26 inferred relationships involving `ScanContext` (e.g. with `ConsentGate` and `Fetcher`) actually correct?**
  _`ScanContext` has 26 INFERRED edges - model-reasoned connections that need verification._
- **Are the 20 inferred relationships involving `Settings` (e.g. with `ConsentGate` and `Path`) actually correct?**
  _`Settings` has 20 INFERRED edges - model-reasoned connections that need verification._
- **Are the 14 inferred relationships involving `Artifact` (e.g. with `ScanResult` and `Artifact`) actually correct?**
  _`Artifact` has 14 INFERRED edges - model-reasoned connections that need verification._