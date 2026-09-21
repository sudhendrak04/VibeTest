# VibeTest — Pending Tasks

Tasks deliberately deferred to later stages. Review this file at the start of each stage.
Do NOT start these early unless the stage gate says so.

Legend: `[ ]` not started · `[~]` in progress · `[x]` done

---

## STAGE: Testing & Evaluation (target: Weeks 10–13)

> Reason for deferral (team decision): target acquisition and live testing happen
> only AFTER the product is built. This whole section is on hold until then.

### 1. Owned vibe-coded targets (Pool 1 — committed core)
- [ ] Draft the "planted vulnerability specification": exact misconfigurations to plant
      (Supabase RLS off, `using(true)` policy, service-role key in client bundle,
      open Firebase RTDB/Firestore rules, exposed `.env`, source maps on, debug configs)
      + a label file per target (what is planted, where, expected detector)
- [ ] Build 5–10 owned demo apps (Next.js + Supabase free tier / Firebase free tier),
      vibe-coded style, deployed on Vercel/Netlify/Render free tiers
- [~] Register every owned target in `eval/targets.yaml` with its ground-truth labels
      (all 5 existing fixtures registered — session 16; append new apps as they are built)

### 2. Local OSS vulnerable apps (Pool 2 — committed core)
- [ ] Docker setup: OWASP Juice Shop, DVWA, crAPI (stretch: WebGoat, VAmPI, bWAPP)
- [ ] Record which of our detectors each app can validate (Layer-1 detectors mostly)

### 3. Third-party / research resources — verify before use
- [ ] gapbench (gapbench.vibe-eval.com): READ TERMS before pointing the tool at it;
      treat as bonus validation only, never as primary ground truth
- [ ] VibeVulns dataset (arXiv:2606.23130): check for a public artifact; if none,
      email the authors requesting it
- [ ] SusVibes (github.com/LeiLiLab/susvibes, MIT): only relevant if repo-scan mode
      gets built (stretch goal)

### 4. Authorized real-world targets (Pool 3 — stretch, high paper value)
- [ ] Draft permission-request email template + consent-record format
      (offered by advisor; team deferred to this stage)
- [ ] Shortlist candidate apps from directories:
      JefferyLee/awesome-vibe-coded-apps (~3,251 apps), madewithlovable.com,
      madewithbolt.com, lovables.love (has "Verified Owner" badges), gitfound.app/tag/lovable
- [ ] Send outreach emails EARLY (target: Weeks 6–8 — response latency is weeks)
- [ ] Store written permissions in the repo (appendix); no permission = no scan

### 5. Passive observation sample (Pool 4 — cheap paper garnish)
- [ ] Define the passive-only scan profile: fetch only what a normal browser receives
      (HTML, headers, public JS bundles). NO payloads, NO login attempts,
      NO reading/writing anyone's database — even if "readable with the anon key"
- [ ] Run on 50–200 directory apps; produce one prevalence table for the paper

### 6. Demo-day safety
- [ ] Un-pause Supabase free-tier projects the week before the demo
      (free projects pause after ~7 days of inactivity)
- [ ] Pre-compute + cache LLM explanations for all demo targets (`--no-llm` fallback ready)
- [ ] Confirm authorized online scanner test beds as live-URL backup:
      testphp.vulnweb.com, testhtml5.vulnweb.com, demo.testfire.net

---

## STAGE: Evaluation & Paper (target: Weeks 12–14)

- [ ] OWASP ZAP baseline comparison runs on Pools 1–2
- [ ] Template-vs-LLM explanation quality rating (team-rated; if ANY outside
      participants are involved → check university ethics/IRB requirements FIRST —
      approval has lead time)
- [ ] Freeze all numbers before Results section drafting (Week 13 checkpoint)

---

## Legal boundary reminder (applies to every task above)

Passive observation of third-party sites (what any browser receives) = low risk.
Active interaction with third-party sites (payloads, auth attempts, DB reads/writes)
= NOT allowed without written owner permission. When in doubt, don't.
