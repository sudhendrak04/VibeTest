# Owned demo fixtures (intentionally vulnerable, FAKE data only)

These are **deliberately broken web apps owned by this project** — our legal, safe
demo/testing targets (Pool 1 seed — see `PENDING.md`). All secrets here are FAKE.

## `demo_site/` — static vibe-coded-style app

Planted ground truth:

| Planted issue | Detector that must find it | Expected severity |
|---|---|---|
| `/.env` publicly served (fake keys) | `exposed_files` | CRITICAL |
| `package-lock.json` publicly served (lodash 4.17.15, minimist 1.2.0, axios 0.21.1) | `deps_osv` (needs internet for OSV.dev) | HIGH + LOW |
| fake Supabase `service_role` JWT in `static/app.js` | `secrets_bundle` | CRITICAL |
| fake `sb_secret_` key + fake AWS key in `static/app.js` | `secrets_bundle` | CRITICAL |
| no security headers | `headers` | MEDIUM/LOW/INFO |
| `static/app.js.map` publicly accessible (source map) | `source_maps` | LOW |
| `NODE_ENV: "development"` marker in `static/app.js` | `debug_config` | MEDIUM |

The bundle also references Supabase and Sentry, so the report's *Detected technology*
line shows `Sentry · Supabase` (recognition only — not a vulnerability).

Serve + scan:

```
python -m http.server 8125 --bind 127.0.0.1 --directory targets/demo_site
vibetest scan http://localhost:8125/ --out reports/demo_site_report.html
```

## `demo_supabase/` — mock Supabase REST backend (RLS demo)

A local server that emulates PostgREST enough to exercise the `supabase_rls`
detector: `/rest/v1/` lists tables; `users` returns rows (RLS "off", bad);
`profiles` returns `[]` (RLS working, good). The page's bundle carries a
**public anon key** (safe by design — must NOT be reported by `secrets_bundle`).

Serve + scan:

```
python targets/demo_supabase/mock_server.py
vibetest scan http://127.0.0.1:8127/ --out reports/demo_supabase_report.html
```

Expected: CRITICAL "Supabase table readable without a session: users", and
**no** secret finding for the anon key (precision test).

## `demo_firebase/` — mock Firebase Realtime Database (open-rules demo)

A local server that emulates Firebase's RTDB REST API: the bundle carries a
public firebaseConfig, and `/.json` returns FAKE data without credentials
(open Security Rules). Expected: CRITICAL "Firebase database readable without
authentication".

```
python targets/demo_firebase/mock_server.py
vibetest scan http://127.0.0.1:8128/ --out reports/demo_firebase_report.html
```

## `demo_repo/` — a mock GitHub repository (repo-scan mode)

A small "vibe-coded" project with planted flaws, served by
`tools/mock_github.py` as if it were a GitHub archive. Expected findings:
committed `.env` + `serviceAccountKey.json` (CRITICAL via `repo_sensitive_files`),
fake secrets in `src/app.js` (`service_role` JWT, `sb_secret_`, AWS key via
`secrets_bundle`), a dev-build marker (`debug_config`), and outdated dependencies
(`repo_deps` via OSV.dev).

```
python tools/mock_github.py
vibetest scan-repo demo-org/demo-app --github-base http://127.0.0.1:8130
```

## `demo_spa/` — JavaScript-built SPA (rendering demo)

The delivered HTML is an almost-empty shell; the visible content and the app's
JavaScript bundle are injected by JavaScript. Without a browser the scanner sees
only the shell; with Playwright it sees the rendered DOM and the dynamically
loaded `/static/app.js` (which carries the planted fake secrets).

```
python -m http.server 8131 --bind 127.0.0.1 --directory targets/demo_spa
vibetest scan http://127.0.0.1:8131/                # with rendering (needs [crawl])
vibetest scan http://127.0.0.1:8131/ --no-render    # shell only — secrets missed
```
