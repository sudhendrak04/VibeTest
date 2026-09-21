
---

**Problem #2 — `.git/HEAD` detection regex failed on real files** (session: `exposed_files` detector)

- **What happened:** the first version of the `.git/HEAD` check used the pattern `^(ref:\s+refs/|[0-9a-f]{40})\s*$`, which only accepted text ending exactly at `ref: refs/`. Real git HEAD files look like `ref: refs/heads/main`, so genuine repository leaks would have been missed.
- **How we noticed:** the unit test `test_git_head_detected` failed (empty finding list) when the detector's tests first ran.
- **Fix:** changed the pattern to accept the branch path after `refs/`; full test suite green afterwards.
- **Lesson:** content-validation rules must match real-world file formats, not idealised ones — tests caught this before any live scan.

**Problem #3 — Google API key test failed due to a wrong-length fixture** (session: `secrets_bundle` detector)

- **What happened:** `test_google_api_key_is_high_not_critical` failed. The detector expects exactly 35 characters after the `AIza` prefix (real Google keys are 39 characters total). The test string had 36 — the detector was correct; the test data was wrong.
- **How we noticed:** failing unit test with zero findings.
- **Fix:** corrected the fixture to a 39-character key; no detector code changed.
- **Lesson:** verify test data against real-world formats before "fixing" working code.

**Problem #4 — Syntax typo in `headers.py`** (session: project scaffold)

- **What happened:** a stray character was written before one of the header entries (`l "referrer-policy":`), a Python syntax error that would have broken importing the whole detector package.
- **How we noticed:** spotted during review before the first test run — code never executed with it.
- **Fix:** removed the stray character.
- **Lesson:** review new code before running it.

**Problem #5 — Demo website deleted by Windows temp cleanup** (session: demo fixtures)

- **What happened:** the fake demo site used for live scans lived in the Windows temp folder; Windows cleanup deleted it between sessions (discovered when checking where the tests actually ran).
- **Fix:** committed permanent fixture copies inside the repository: `targets/demo_site/` (static planted-vulnerability site) and `targets/demo_supabase/` (mock Supabase backend), plus `targets/README.md` with serve/scan instructions.
- **Lesson:** anything needed for demos or tests must live inside the repo — never in temp folders.

**Problem #6 — Duplicated HTTP helper code in 4 modules** (session: `deps_osv` detector)

- **What happened:** the same two helpers (bounded download read; SPA-fallback detection) were copy-pasted into `exposed_files`, `js_bundle`, `supabase_rls`, and were about to be copied a fourth time for `deps_osv`. Risk: a bug fixed in one copy silently stays in the others.
- **Fix:** extracted both helpers into one shared module (`vibetest/core/http_util.py`) and refactored all callers; full test suite stayed green.
- **Lesson:** extract shared logic into one place at the third copy, not the fifth.

**Problem #7 — Process: work started before explicit approval** (session: project scaffold)

- **What happened:** code scaffolding began after only being asked for planning documents — the team had not approved starting to build yet.
- **Fix:** stopped immediately; confirmed with the team; adopted an explicit "execute this task" pattern — no code is written unless a specific task is named, and documentation is edited only when asked.
- **Lesson:** confirm scope approval before writing code; keep planning and building as separate, explicitly gated steps.

**Problem #8 — Cosmetic: console output encoding / truncation** (ongoing, minor)

- **What happened:** in the command-line output on Windows, some characters render as `�` (e.g. the em-dash in finding titles) and long titles wrap/cut inside the table.
- **Impact:** cosmetic only — the HTML report (the actual deliverable) renders correctly; this affects just the live terminal display.
- **Fix / status:** not fixed yet; optional future cleanup (normalise characters in titles and/or set the console encoding).

The first demo run showed lodash and minimist findings, but axios was silently missing — even though it clearly should be flagged. Root cause: axios's OSV response is 206 KB, and my code had a 64 KB read limit, so the JSON was truncated → parse failed → the check quietly returned nothing. Fixed the limit (2 MB) and added a regression test with a >64 KB response so it can never come back silently. That's now three bugs caught by tests/demos before "shipping" — good material for the paper's engineering-practices section.

x-powered-by check was case-sensitive. The fingerprinter lowercased header names but forgot to lowercase the header value — so the check "express" in "Express" never matched, and Express sites would have gone unrecognized. Caught by: the new unit test test_netlify_hosting_and_express_framework on its first run. Fix: lowercase the header value before comparing; all 49 tests green after. Lesson: normalise both sides of every string comparison — case bugs hide exactly at these boundaries.

binary detection relied only on UTF-8 decode failure. When mapping repo files, I treated "UTF-8 decode succeeds" as "this is a text file" — but binary data containing null/control bytes is valid UTF-8, so a binary .js file slipped through as text. Caught by: the new test test_build_repo_artifact_skips_binary_and_oversized (first run failed: {'blob.js', 'ok.js'} == {'ok.js'}). Fix: added the classic null-byte check before decoding. Lesson: "decodes successfully" ≠ "is text" — use content heuristics, not just encodings.