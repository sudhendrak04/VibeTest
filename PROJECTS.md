# PROJECTS.md — VibeTest Decision Log

All decisions taken so far, with rationale and the alternatives that were considered.
Date of record: 2026-09-12. Status: **frozen for Phase 1** unless the whole team agrees to reopen.

Hard constraints driving every decision: **zero budget** · demo to professors + external
evaluator · **team of 3** (2 builders + 1 paper writer in parallel) · **one semester (15 weeks)**.

---

## 1. Checklist philosophy — DECIDED

**Two-layer checklist, no active exploitation.**

- **Layer 1 — passive baseline (5 checks):** missing security headers (CSP, HSTS,
  frame-ancestors, X-Content-Type-Options, Referrer-Policy) · exposed sensitive files
  (`.env`, `.git/`, configs) · secrets/API keys in client JS bundles · vulnerable
  dependencies (OSV-Scanner) · TLS/CORS basics.
- **Layer 2 — vibe-coding-specific detectors (4–6 checks, the novelty):** Supabase RLS
  missing/permissive (probe `/rest/v1/` with the public anon key — CVE-2025-48757 pattern) ·
  service-role/`sb_secret_` keys in client bundles · Firebase RTDB/Firestore open rules ·
  exposed source maps · framework default/debug configs · client-side-only authorization hints.

**Why:** zero budget (no attack infra) · near-zero legal risk · direct research novelty
(operationalizes findings of arXiv:2606.23130 and CVE-2025-48757) · strong demo story.

**Alternatives rejected:** full OWASP Top 10:2025 breadth (too much for 2 builders;
needs authenticated crawling + active probing) · repo-only static analysis (misses
deployment-layer bugs; weaker demo) · minimal passive-only (too thin for a paper).

## 2. Architecture — DECIDED

**Plugin-based deterministic pipeline + LLM explanation layer (hybrid).**

- Deterministic core ⇒ reproducible evaluation (paper requirement).
- Plugin split ⇒ the 2 builders work in parallel without blocking (§7).
- LLM touches findings only, never the target ⇒ LLM weakness degrades prose, never correctness.

**Alternatives rejected:** monolithic pipeline (blocks parallel work) · pure rule-based,
no LLM (loses non-expert reporting + a paper angle) · **agentic/LLM-orchestrated**
(impractical at zero budget: AutoPenBench measured ~21% success for autonomous agents
even with frontier models; laptop 4–8B models too weak; free API quotas — GitHub Models
50–150 req/day, Gemini ~1,500/day shared across dev+eval+demo — can't feed agent loops;
non-determinism poisons evaluation) · **microservices** (scale theater for a student demo).

## 3. LLM dependency — DECIDED

**LLM yes, explanation/report layer only, local via Ollama.**

- Primary: **Qwen3 8B** Q4_K_M (~6 GB RAM; 16 GB laptops) · low-spec: **Phi-4-mini**
  (~2.5 GB; 8 GB laptops) · code-heavy findings: **Qwen2.5-Coder 7B**.
- temperature 0 · fixed seed · pinned model digest · JSON-schema structured output.
- Cache LLM output per finding-hash; ship `--no-llm` template fallback (demo insurance).

**Alternatives rejected:** free-tier hosted APIs as primary (demo-day Wi-Fi risk; shared
quota; terms change without notice — kept only as dev-time secondary) · no-LLM templates
(kept as fallback + paper baseline) · LLM in detection logic (hallucinated findings,
non-reproducible, slow on CPU).

## 4. Tech stack — DECIDED

Python 3.12+ · httpx + Playwright · **Katana (MIT, external binary) for URL/endpoint
discovery** · selectolax/BeautifulSoup · SQLite (SQLModel/SQLAlchemy) ·
Pydantic · Typer CLI · FastAPI + Jinja2 dashboard (localhost-only, read-only) ·
Jinja2 HTML report + WeasyPrint PDF (Week 9) · Gitleaks/OSV-Scanner/(stretch: Semgrep CE) as
subprocess plugins · ollama python client · pytest + pytest-snapshot.

**Alternatives rejected:** httpx-only lite crawler (misses JS-rendered SPAs — fatal for
this target class) · Go stack (learning curve) · Node/TS (weaker security-lib ecosystem).

## 5. Delivery format — DECIDED

**CLI-first + locally-served dashboard (presenter's laptop) as the primary demo path;
Hugging Face Spaces public mirror for evaluator self-service; self-contained HTML report
as the leave-behind artifact.**

**Rejected / flagged:** Render free tier (15-min spin-down → 30–60 s cold start mid-demo;
free Postgres dies after 30 days) · Railway / Fly.io / Koyeb (no usable free tier) ·
Vercel/Netlify for hosting the scanner (serverless timeouts kill long scans) · browser
extension (passive-only scope cuts Layer-2 detectors) · API-first (weak demo) ·
background/scheduled agent (highest cost + highest ethical risk).

## 6. Consent model — DECIDED

**Owned-targets-only, enforced by a hard allowlist gate in the tool.**

- Pool 1: 5–10 team-built vibe-coded apps with planted vulns (perfect ground truth).
- Pool 2: self-hosted OSS vulnerable apps in Docker (Juice Shop, DVWA, crAPI, …).
- Stretch: Pool 3 (3–5 real apps with written owner permission), Pool 4 (passive-only
  observation sample). Ownership-verification flow (meta-tag/file upload) = stretch goal.

**Rejected:** meta-tag verification as the primary model (build cost, residual abuse risk) ·
passive-only public scanning as the core (different project; collides with published
10,517-app study) · DNS TXT (target population on `*.vercel.app`-style subdomains can't set TXT).

## 7. Feasibility & task split — DECIDED

- **Week 1–2 joint:** freeze Artifact + Finding Pydantic schemas (the unblocking contract).
- **Builder A — acquisition & core:** CLI skeleton, crawler (httpx+Playwright), JS-bundle
  extractor, tech fingerprinter, artifact store.
- **Builder B — detection & reporting:** detector framework, 9–11 detectors, severity
  scoring, report generator, LLM explanation layer. Works against mock artifacts from day 1.
- **Committed scope:** SPA-capable crawler · 8–10 detectors · HTML report + local dashboard ·
  local-LLM explanations + template fallback · eval harness over ~10 targets.
- **Stretch:** GitHub-repo input mode · Semgrep integration · 2–3 more detectors.
- **Non-goals:** accounts, multi-tenancy, distributed scanning, authenticated crawling,
  active exploitation, auto-fix.

## 8. Research paper angle — DECIDED

**"Design and evaluation of a hybrid deterministic + LLM-explanation scanner for
vibe-coded web applications"** with three contributions: (1) tool/architecture,
(2) a small **labeled benchmark of vibe-coded apps** (the differentiator — VibeVulns
measured the wild, SusVibes benchmarks code generation; no reusable labeled *detection*
benchmark for deployed vibe-coded web apps exists), (3) evaluation: P/R vs ground truth,
ZAP baseline comparison, template-vs-LLM explanation rating.

Writer drafts immediately: related work, threat model, methodology (after W2–3 freeze),
benchmark design, evaluation plan. Waits for: results, numbers, case studies.

## 9. Timeline — DECIDED

15-week plan with writer sync checkpoints: W2 checklist freeze · W3 architecture freeze +
diagram · W5 first end-to-end sample scan · W7 mid-project demo-able skeleton ·
W9 sample report PDF · W10–11 target set frozen · W12–13 raw results → numbers locked ·
W14 full paper revision · W15 buffer + final demo. (Full week-by-week table in project notes.)

## 10. Testing-target resources — DECIDED (execution deferred)

Five-pool target portfolio (owned · local OSS · authorized real-world · passive sample ·
authorized online test beds). **Team decision: all acquisition/testing tasks are deferred
until after the product is built** — tracked in `PENDING.md`.

## 11. Crawler strategy: Katana for URL discovery — DECIDED

**Katana (ProjectDiscovery, MIT) handles URL/endpoint discovery; our own httpx +
Playwright code still does fetching, JS-bundle extraction, and tech fingerprinting.**

- Katana output is converted into our `Artifact` contract — detectors are unaffected.
- All Katana-derived requests re-pass the consent gate; Katana runs **crawl-only**
  (no fuzzing) against allowlisted targets only.
- Rationale: production-grade endpoint enumeration for $0; crawling is not our novelty
  (detectors + the labeled benchmark are); wrapping established tools is standard
  practice in the pentest-agent literature (PentestGPT et al.).
- Dependency mode: **soft — DECIDED** (graceful fallback to plain httpx crawl if the
  binary is missing); keeps the demo day robust on any machine.

**Alternatives rejected:** hand-rolled URL discovery (full control, but weeks of effort
on a solved problem) · OWASP ZAP spider (heavy JVM/Docker dependency; overlaps our
detectors — ZAP stays only as the paper's baseline comparison scanner).

---

## Hidden-cost flag log (verified 2026-09)

Render free tier: 15-min spin-down; free Postgres expires at 30 days · Railway/Fly.io/Koyeb:
no usable free tier · GitHub Models: prototyping-only ToS, 50–150 req/day · HF Inference
Providers: ~$0.10/month credit (unusable) · Supabase free projects pause after ~7 days idle ·
Gemini free tier: usable (1,500 req/day, no card) but limits change without notice.
