# VibeTest — Architecture & Data Flow

Status: **frozen for Phase 1** (Week 3 checkpoint artifact for the paper-writer).
Changes require agreement of all three team members. See `PROJECTS.md` for the
decision rationale and `AGENTS.md` for coding conventions.

## 1. Design summary

Plugin-based **deterministic pipeline** + **local-LLM explanation layer** (hybrid).
The LLM never touches the target and never participates in detection — it only turns
confirmed findings into plain-English explanations for non-expert users.
URL/endpoint **discovery is delegated to Katana** (ProjectDiscovery, MIT, external
binary); fetching, JS-bundle extraction, and fingerprinting stay in-house.

```
URL input
  → consent/allowlist gate            (core/consent.py — every request passes through)
  → discovery: Katana (MIT, external) (acquisition/katana.py — URL/endpoint enumeration)
  → fetch + extract (httpx+Playwright)(acquisition/crawler.py, js_bundle.py)
  → Artifact (CONTRACT 1)             (schemas/artifacts.py)
  → detector plugins [1..N]           (detectors/ — one vulnerability class per file)
  → Findings (CONTRACT 2)             (schemas/findings.py)
  → aggregate: dedup + severity       (analysis/)
  → explanation: local Ollama | template fallback   (reporting/explain.py)
  → HTML report / localhost dashboard (reporting/, web/)
```

## 2. Repository layout

```
VibeTest/
├── AGENTS.md  PROJECTS.md  PENDING.md  docs/ARCHITECTURE.md
├── pyproject.toml  vibetest.toml
├── vibetest/
│   ├── cli.py                  # Typer entry: scan / targets / serve
│   ├── config.py               # settings + allowlist loading (vibetest.toml)
│   ├── schemas/
│   │   ├── artifacts.py        # CONTRACT 1 (Builder A produces)
│   │   ├── findings.py         # CONTRACT 2 (Builder B produces)
│   │   └── scan.py             # ScanResult (artifact + findings + metadata)
│   ├── core/
│   │   ├── consent.py          # allowlist gate
│   │   ├── orchestrator.py     # pipeline runner (fetcher injectable for tests)
│   │   └── store.py            # SQLite persistence
│   ├── acquisition/            # ===== BUILDER A =====
│   │   ├── katana.py           # Katana wrapper — URL/endpoint discovery (external MIT binary, soft dep)
│   │   ├── crawler.py          # httpx fetch of discovered URLs + rendering hook
│   │   ├── render.py           # optional Playwright rendering of SPA shells (browser requests gated)
│   │   ├── github_repo.py      # public-repo archive download/extract/mapping (repo mode)
│   │   ├── js_bundle.py        # bundle download & extraction
│   │   └── fingerprint.py      # tech detection (Next.js, Supabase, Firebase…)
│   ├── detectors/              # ===== BUILDER B =====
│   │   ├── base.py             # BaseDetector ABC + ScanContext
│   │   ├── registry.py         # plugin registry
│   │   ├── headers.py  exposed_files.py  secrets_bundle.py
│   │   ├── deps_osv.py  cors_tls.py                        # Layer 1 (passive)
│   │   ├── supabase_rls.py  service_role_key.py
│   │   ├── firebase_rules.py  source_maps.py  debug_config.py  # Layer 2 (vibe-specific)
│   ├── analysis/
│   │   ├── aggregate.py        # dedup by fingerprint, severity ordering
│   │   └── severity.py         # category → CWE / OWASP-2025 / default severity map
│   ├── reporting/
│   │   ├── explain.py          # local Ollama (JSON mode, temp 0) + template fallback
│   │   ├── html_report.py      # Jinja2 → self-contained HTML
│   │   └── pdf.py              # W9: WeasyPrint (optional extra)
│   └── web/
│       └── app.py              # localhost dashboard (FastAPI + Jinja2, read-only)
├── tests/
│   ├── conftest.py             # mock Artifact fixture (Builder B works from day 1)
│   └── test_*.py               # contracts, consent gate, end-to-end pipeline
└── eval/
    ├── harness.py              # W11: golden-file eval runner (precision/recall)
    └── targets.yaml            # W10: owned targets + ground-truth labels
```

## 3. The two contracts (Week 2 freeze)

**Artifact** — produced by acquisition, the *only* input detectors may see:
`scan_id, target_url, fetched_at, pages[] (url, status_code, headers, html),
js_bundles[] (url, content, source_map_url?), endpoints[] (url, method, params),
tech (framework, hosting, backend_services[]), tls, cookies[], errors[]`

**Finding** — emitted by every detector:
`finding_id, detector_id, category, cwe_id, owasp_2025, severity, confidence,
title, evidence[] (url, snippet, detail), remediation_hint, explanation (nullable —
filled later by the explanation layer)`

## 4. Detector interface

```python
class BaseDetector(ABC):
    id: ClassVar[str]
    name: ClassVar[str]
    layer: ClassVar[int] = 1              # 1 = passive baseline · 2 = vibe-specific
    needs_probes: ClassVar[bool] = False  # Layer-2 detectors declare extra requests

    @abstractmethod
    def run(self, artifact: Artifact, ctx: ScanContext) -> list[Finding]: ...
```

Rules: detectors never fetch on their own — they reason over the Artifact. Layer-2
detectors that need extra requests (e.g. the Supabase `/rest/v1/` probe) set
`needs_probes = True` and use `ctx.http`, which the orchestrator only provides when
probes are enabled — and even then, every request goes through the consent gate.

## 5. Data flow (one scan, end to end)

1. `vibetest scan <url>` → **consent gate**: not on allowlist → hard refuse + log.
2. **Acquisition** (A): consent-gated Katana crawl → discovered URLs → httpx fetch →
   SPA? → Playwright render → bundles, endpoints, fingerprint → `Artifact` → SQLite.
3. **Detection** (B): registry fans out enabled detectors over the Artifact → `Finding[]`.
4. **Analysis** (B): dedup by `(detector_id, evidence-hash)` → severity ordering.
5. **Explanation** (B): per finding — cache hit? else Ollama (temp 0, JSON schema),
   else template → fill `explanation`.
6. **Report** (B): Jinja2 → self-contained HTML (+PDF in W9); dashboard reads SQLite —
   scan once, re-render without re-scanning.

## 6. Build order (Weeks 1–5, builders in parallel)

| Week | Builder A (acquisition & core) | Builder B (detection & reporting) |
|---|---|---|
| 1–2 | schemas co-authored & frozen; CLI skeleton | detector framework + detectors vs mock artifacts |
| 3 | httpx fetcher + Katana discovery wrapper | headers + exposed_files detectors |
| 4 | Playwright SPA rendering + js_bundle | secrets-in-bundle + OSV deps detectors |
| 5 | tech fingerprinter | **supabase_rls detector (flagship)** → Friday end-to-end run |

## 7. Deferred / open decisions (recorded so nobody re-litigates them)

- **Katana dependency mode** — DECIDED: soft dependency (optional binary, graceful
  fallback to plain httpx crawl). Full rationale in PROJECTS.md §11; not an open item.
- **Dashboard** — DECIDED: FastAPI + Jinja2, localhost-only; scan launcher + results viewer, gated by the same consent allowlist (single-flight).
- **PDF export** (WeasyPrint): Week 9, optional dependency (heavy on Windows).
- **Playwright** — implemented: optional `[crawl]` extra (`pip install -e ".[crawl]"` + `playwright install chromium`); renders SPA shells only; every browser request is consent-gated; graceful raw-HTML fallback.
- **Ownership-verification flow** (meta-tag/file upload): stretch goal, post-MVP.
