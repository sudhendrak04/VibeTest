# AGENTS.md — VibeTest

Guidance for AI agents (and humans) working in this repository. Read this before
writing any code. Update this file whenever a decision, convention, or structure changes.

## What this project is

VibeTest is a university final-year major project: an **automated, authorization-gated
security scanner for "vibe-coded" web applications** (AI-generated apps hosted on free
platforms like Vercel/Netlify/Render, or with public GitHub source). It crawls a target,
detects vulnerabilities with a focus on vibe-coding-specific failure modes (e.g.,
Supabase RLS misconfiguration — the CVE-2025-48757 pattern), and reports findings
in plain English to non-expert users, assisted by a **local** LLM.

Phase 1 scope: scan/crawl → detect → report. **Auto-fix is explicitly out of scope** (future work).

## Hard constraints (never violate)

1. **Zero budget.** No paid APIs, no paid subscriptions, no paid hosting. Only
   free/open-source tools, free-tier services, and open-weight local LLMs (Ollama).
2. **Owned/authorized targets only.** The scanner must NEVER run against a target not
   on the explicit allowlist (`config`/consent gate). No active exploitation anywhere —
   passive checks + gentle unauthenticated probes only. Repo mode (`vibetest scan-repo`)
   is passive analysis of PUBLIC repositories only — it never contacts the deployed site.
   See `PENDING.md` legal note.
3. **Deterministic core.** Detection must be reproducible: same target → same findings.
   The LLM may ONLY touch the explanation/report layer, never detection logic.
4. **Student-demo scope.** Do not over-engineer for production scale (no Kubernetes,
   no microservices, no multi-tenancy, no user accounts).

## Team & workflow

- Team of 3: **Builder A** (acquisition & core), **Builder B** (detection & reporting),
  **Writer** (research paper, works in parallel — needs frozen decisions, not finished code).
- The **Artifact** and **Finding** Pydantic schemas are the binding contract between
  builders. They freeze in Week 2. Changing them requires all three members to agree.
- Weekly integration: end-to-end run every Friday.
- **After every coding session: update `PROGRESS.md`** (plain-language implementation log
  for the project guide/professor — see Key files).
- **At the end of every coding session: report any problems encountered** (bugs found,
  failures, blockers — including how they were noticed and fixed) so the team can log
  them in `PROBLEMS.md`.
- One-semester (15-week) plan; see `PROJECTS.md` §9.

## Architecture (decided — see PROJECTS.md for rationale)

Plugin-based deterministic pipeline + LLM explanation layer:

```
URL → consent/allowlist gate → Katana discovery (external MIT binary)
    → fetch + extract (httpx + Playwright)
    → Artifact store (SQLite) → detector plugins [1..N]
    → aggregate (dedup + severity) → LLM explanation (local Ollama, temp 0,
      template fallback via --no-llm) → HTML report / local dashboard
```

Repo mode (`vibetest scan-repo owner/name`) downloads a PUBLIC GitHub archive and
runs the same detectors statically — no live requests to the deployed site.

## Tech stack (decided)

- Python 3.12+ · Pydantic (schemas) · Typer (CLI) · SQLite via SQLModel/SQLAlchemy
- **Katana** (ProjectDiscovery, MIT — external Go binary for URL/endpoint discovery;
  soft dependency: graceful fallback to plain httpx crawl if the binary is missing)
- httpx + Playwright (headless Chromium — optional `[crawl]` extra; renders SPA shells only; every browser request is consent-gated; graceful raw-HTML fallback when not installed)
- Detectors: own rules + Gitleaks / OSV-Scanner (and stretch: Semgrep CE) as subprocess plugins
- Reporting: Jinja2 → self-contained HTML (+ WeasyPrint PDF, Week 9) · Dashboard: FastAPI + Jinja2, localhost-only; can trigger scans, but ONLY through the same consent gate (allowlist enforced in the pipeline, single-flight)
- LLM: Ollama, JSON-schema structured output, temperature 0, pinned model digest.
  Primary: Qwen3 8B Q4_K_M (16 GB RAM) · Fallback: Phi-4-mini (8 GB RAM) ·
  Code-heavy: Qwen2.5-Coder 7B. Explanation layer ONLY (`--llm`); automatic
  template fallback on any failure; per-finding cache in `.llm_cache.json`.
  Model names in `vibetest.toml` must match locally installed Ollama tags.
- Testing: pytest + pytest-snapshot (golden-file scan results = reproducibility evidence)

## Coding conventions

- All data crossing module boundaries MUST be a Pydantic model from `vibetest/schemas/`.
- Every detector implements the `Detector` protocol in `vibetest/detectors/base.py`
  and is registered in `vibetest/detectors/registry.py`. One vulnerability class = one file.
- Detectors receive an `Artifact` and return `list[Finding]`; they never do their own
  network fetches (all fetching lives in `vibetest/acquisition/`).
- Every network request to a target goes through the consent gate first. No exceptions.
  This includes Katana: crawl-only (no fuzzing), allowlisted entries only, and every
  Katana-derived URL is re-checked by the gate before being fetched.
- Playwright rendering must keep `render.should_block` authoritative: the browser may
  never request a non-allowlisted host (images/fonts/media are skipped for speed).
- LLM calls only inside `vibetest/reporting/explain.py`; results cached per finding-hash.
- New detector ⇒ add golden-file test fixture under `tests/`.

## Key files

- `PROJECTS.md` — full decision log (what was decided, why, alternatives rejected)
- `PROGRESS.md` — plain-language implementation log (professor-facing); **update after every coding session**
- `PROBLEMS.md` — team-maintained log of real problems faced and how they were fixed
  (agent reports issues at session end; the team updates the file)
- `PENDING.md` — deferred tasks (testing-target acquisition lives there until Week 10)
- `AGENTS.md` — this file; keep it current

## Non-goals (Phase 1)

User accounts · multi-tenancy · distributed scanning · authenticated crawling ·
active exploitation · auto-fixing vulnerabilities · agentic/LLM-orchestrated scanning
(evaluated and rejected — see PROJECTS.md §2/§3).

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, invoke the `skill` tool with `skill: "graphify"` before doing anything else.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
