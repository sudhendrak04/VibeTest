"""HTML templates for the local dashboard (inline strings — same approach as the
report, avoids package-data configuration and keeps everything offline)."""

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} — VibeTest</title>
<style>
  :root{
    --bg:#f3f5f9; --card:#fff; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0;
    --accent:#4f46e5; --accent-2:#4338ca;
    --critical:#b00020; --high:#dc2626; --medium:#d97706; --low:#0284c7; --info:#64748b;
    --radius:14px; --shadow:0 1px 2px rgba(15,23,42,.06), 0 10px 26px -18px rgba(15,23,42,.35);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  h1,h2,h3{margin:0;line-height:1.25}
  a{color:var(--accent);text-decoration:none}
  a:hover{text-decoration:underline}
  .muted{color:var(--muted);font-size:.85rem}
  .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.82rem}
  .hidden{display:none}
  .topbar{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:.6rem;padding:.8rem 1.4rem;color:#fff;background:linear-gradient(90deg,#0b1220,#131f3a);box-shadow:0 2px 14px rgba(2,6,23,.28)}
  .brand{display:flex;align-items:center;gap:.55rem;font-weight:700;letter-spacing:.2px}
  .brand svg{color:#818cf8}
  .topbar .pill{margin-left:auto;font-size:.72rem;color:#c7d2fe;background:rgba(129,140,248,.14);border:1px solid rgba(129,140,248,.35);padding:.28rem .65rem;border-radius:999px;white-space:nowrap}
  main{max-width:1020px;margin:1.6rem auto 2.5rem;padding:0 1rem}
  .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:1.15rem 1.3rem;margin-bottom:1rem}
  .card h2{font-size:1.02rem}
  /* ---------- overview stats ---------- */
  .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin-bottom:1.1rem}
  .stat{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:.9rem 1rem}
  .stat .num{font-size:1.4rem;font-weight:800}
  .stat .label{color:var(--muted);font-size:.74rem;text-transform:uppercase;letter-spacing:.07em;margin-top:.1rem}
  .stat.critical .num{color:var(--critical)}
  .stat.high .num{color:var(--high)}
  .stat.medium .num{color:var(--medium)}
  .stat.clean .num{color:#16a34a}
  /* ---------- launcher ---------- */
  .hint{color:var(--muted);font-size:.85rem;margin:.35rem 0 .8rem}
  form{display:flex;gap:.55rem;flex-wrap:wrap}
  input[type=url]{flex:1;min-width:260px;padding:.62rem .8rem;border:1px solid #cbd5e1;border-radius:10px;font-size:.92rem;outline:none;transition:border .15s, box-shadow .15s}
  input[type=url]:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,70,229,.15)}
  button{padding:.62rem 1.15rem;border:0;border-radius:10px;background:var(--accent);color:#fff;font-weight:700;font-size:.92rem;cursor:pointer;transition:background .15s}
  button:hover{background:var(--accent-2)}
  button:disabled{background:#94a3b8;cursor:wait}
  .scan-box{margin-top:.9rem;border:1px solid var(--line);border-radius:10px;padding:.75rem .9rem;background:#f8fafc}
  .scan-line{display:flex;align-items:center;gap:.5rem;font-size:.88rem;color:#334155}
  .spinner{display:inline-block;width:13px;height:13px;border:2px solid #c7d2fe;border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex:none}
  @keyframes spin{to{transform:rotate(360deg)}}
  .progress{height:6px;background:#e2e8f0;border-radius:999px;overflow:hidden;margin-top:.6rem}
  .progress-bar{height:100%;width:38%;border-radius:999px;background:linear-gradient(90deg,#818cf8,#4f46e5);animation:slide 1.2s ease-in-out infinite}
  @keyframes slide{0%{transform:translateX(-110%)}100%{transform:translateX(285%)}}
  .scan-error{margin-top:.9rem;border:1px solid #fecaca;background:#fef2f2;color:#991b1b;border-radius:10px;padding:.65rem .85rem;font-size:.86rem}
  /* ---------- history ---------- */
  .section-head{display:flex;justify-content:space-between;align-items:baseline;margin:1.3rem 0 .7rem}
  .section-head h1{font-size:1.08rem}
  .scan-card{display:flex;align-items:center;gap:1rem;transition:transform .12s, box-shadow .12s;color:inherit}
  .scan-card:hover{transform:translateY(-1px);box-shadow:0 14px 30px -18px rgba(15,23,42,.45);text-decoration:none}
  .scan-main{flex:1;min-width:0}
  .scan-url{font-weight:650;font-size:.95rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .bar{display:flex;height:7px;background:#eef2f7;border-radius:999px;overflow:hidden;margin-top:.55rem}
  .bar-seg{height:100%}
  .bar-seg.critical{background:var(--critical)}
  .bar-seg.high{background:var(--high)}
  .bar-seg.medium{background:var(--medium)}
  .bar-seg.low{background:var(--low)}
  .bar-seg.info{background:var(--info)}
  .badges{display:flex;gap:.35rem;flex-wrap:wrap;justify-content:flex-end}
  .badge{font-size:.68rem;font-weight:800;letter-spacing:.04em;padding:.2rem .55rem;border-radius:999px;color:#fff;text-transform:uppercase;white-space:nowrap}
  .badge.critical{background:var(--critical)}
  .badge.high{background:var(--high)}
  .badge.medium{background:var(--medium)}
  .badge.low{background:var(--low)}
  .badge.info{background:var(--info)}
  .badge.none{background:#e2e8f0;color:#475569}
  .chev{color:#94a3b8;font-weight:700}
  .empty{text-align:center;color:var(--muted);padding:2.6rem 1rem;font-size:.92rem}
  /* ---------- detail ---------- */
  .back{display:inline-block;margin-bottom:.7rem;font-size:.88rem}
  .detail-head{display:flex;gap:1rem;align-items:flex-start;flex-wrap:wrap}
  .detail-head .left{flex:1;min-width:240px}
  .detail-head h1{font-size:1.2rem;word-break:break-all}
  .chips{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.55rem}
  .chip{background:#eef2ff;color:#3730a3;border:1px solid #e0e7ff;padding:.2rem .65rem;border-radius:999px;font-size:.75rem;font-weight:600}
  .btn{display:inline-block;padding:.55rem 1rem;border-radius:10px;background:var(--accent);color:#fff;font-weight:700;font-size:.86rem;white-space:nowrap}
  .btn:hover{background:var(--accent-2);text-decoration:none}
  .actions{display:flex;flex-direction:column;gap:.5rem;align-items:flex-end}
  .btn.secondary{background:#fff;color:#3730a3;border:1px solid #c7d2fe}
  .btn.secondary:hover{background:#eef2ff}
  .finding{border-left:6px solid #cbd5e1}
  .finding.critical{border-left-color:var(--critical)}
  .finding.high{border-left-color:var(--high)}
  .finding.medium{border-left-color:var(--medium)}
  .finding.low{border-left-color:var(--low)}
  .finding.info{border-left-color:var(--info)}
  .finding-head{display:flex;align-items:center;gap:.55rem;flex-wrap:wrap}
  .finding-head h3{font-size:1rem}
  .explain{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:.75rem .9rem;margin:.7rem 0;white-space:pre-line;font-size:.9rem;color:#334155}
  details{margin:.45rem 0}
  details summary{cursor:pointer;color:#334155;font-size:.86rem;font-weight:600}
  pre{background:#0f172a;color:#e2e8f0;padding:.65rem .8rem;border-radius:8px;overflow:auto;font-size:.78rem;white-space:pre-wrap;margin:.45rem 0}
  .todo{border:1px solid #bbf7d0;background:#f0fdf4;border-radius:10px;padding:.65rem .85rem;margin-top:.6rem}
  .todo strong{color:#166534;font-size:.82rem;text-transform:uppercase;letter-spacing:.05em}
  .todo p{margin:.25rem 0 0;font-size:.88rem;color:#14532d}
  .confirm{display:flex;align-items:flex-start;gap:.5rem;width:100%;margin-top:.6rem;font-size:.82rem;color:#475569;line-height:1.4}
  .confirm input{margin-top:.18rem;flex:none}
  .chip.kind{background:#111827;color:#f8fafc;border-color:#111827}
  .foot{max-width:1020px;margin:0 auto 2.2rem;padding:0 1rem;color:#94a3b8;font-size:.78rem;text-align:center}
</style>
</head>
<body>
<header class="topbar">
  <span class="brand">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 3l7 4v5c0 4.6-3 7.6-7 9-4-1.4-7-4.4-7-9V7l7-4z"/><path d="M9 12l2 2 4-4"/>
    </svg>
    VibeTest
  </span>
  <span class="pill">localhost only · owned/authorized targets only</span>
</header>
<main>
{{ body | safe }}
</main>
<footer class="foot">VibeTest — automated security scanner for vibe-coded web apps · reports are informational, not a guarantee of security</footer>
<script>
const form = document.getElementById("scan-form");
if (form) {
  const msg = document.getElementById("scan-msg");
  const err = document.getElementById("scan-error");
  const box = document.getElementById("scan-box");
  const btn = document.getElementById("scan-btn");

  const showError = (text) => {
    err.textContent = text;
    err.classList.remove("hidden");
    box.classList.add("hidden");
    btn.disabled = false;
  };

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    err.classList.add("hidden");
    box.classList.remove("hidden");
    msg.textContent = "Starting scan…";
    btn.disabled = true;

    let resp;
    try {
      resp = await fetch("/api/scan", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
          url: document.getElementById("scan-url").value.trim(),
          authorized: document.getElementById("scan-authorized").checked,
        }),
      });
    } catch (networkError) {
      showError("Could not reach the dashboard.");
      return;
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      showError(data.detail || "Scan refused.");
      return;
    }
    const {job_id, mode} = await resp.json();
    const started = Date.now();
    while (true) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      let job;
      try {
        job = await (await fetch("/api/scan/" + job_id)).json();
      } catch (networkError) {
        msg.textContent = "Waiting for the scanner…";
        continue;
      }
      if (job.status === "done") { window.location = "/scan/" + job.scan_id; return; }
      if (job.status === "failed") { showError("Scan failed: " + (job.error || "unknown error")); return; }
      const secs = Math.round((Date.now() - started) / 1000);
      const verb = mode === "repo" ? "Downloading & analysing repository… " : "Scanning… ";
      msg.textContent = verb + secs + "s — this can take a little while";
    }
  });
}

const pdfBtn = document.getElementById("pdf-btn");
if (pdfBtn) {
  const hint = document.getElementById("pdf-hint");
  pdfBtn.addEventListener("click", async () => {
    pdfBtn.disabled = true;
    try {
      const resp = await fetch(pdfBtn.dataset.href);
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.detail || "PDF export unavailable");
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = pdfBtn.dataset.filename || "vibetest-report.pdf";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      // Fallback: open the HTML report and point at the browser's Print-to-PDF
      window.open(pdfBtn.dataset.reportHref, "_blank");
      if (hint) hint.classList.remove("hidden");
    } finally {
      pdfBtn.disabled = false;
    }
  });
}
</script>
</body>
</html>
"""

LIST_BODY = """
<div class="stats">
  <div class="stat"><div class="num">{{ stats.scans }}</div><div class="label">Scans</div></div>
  <div class="stat critical"><div class="num">{{ stats.critical }}</div><div class="label">Critical</div></div>
  <div class="stat high"><div class="num">{{ stats.high }}</div><div class="label">High</div></div>
  <div class="stat"><div class="num">{{ stats.total }}</div><div class="label">Total findings</div></div>
</div>

<section class="card">
  <h2>Scan a website or GitHub repo</h2>
  <p class="hint">Websites: authorized targets only — the consent gate refuses anything else.
  GitHub: public repositories — passive static analysis, no requests to any deployed site.</p>
  <form id="scan-form">
    <input id="scan-url" type="text" placeholder="https://your-app.vercel.app  ·  github.com/owner/repo" required>
    <label class="confirm">
      <input type="checkbox" id="scan-authorized" required>
      I confirm I own this target or have written permission to test it (or it is a public repository).
    </label>
    <button type="submit" id="scan-btn">Start scan</button>
  </form>
  <div id="scan-box" class="scan-box hidden">
    <div class="scan-line"><span class="spinner"></span><span id="scan-msg">Starting…</span></div>
    <div class="progress"><div class="progress-bar"></div></div>
  </div>
  <div id="scan-error" class="scan-error hidden"></div>
</section>

<div class="section-head">
  <h1>Scan history</h1>
  <span class="muted">{{ scans | length }} scan(s)</span>
</div>
{% if scans %}
{% for s in scans %}
<a class="card scan-card" href="/scan/{{ s.row.scan_id }}">
  <div class="scan-main">
    <div class="scan-url">{{ s.row.target_url }}</div>
    <div class="muted">{{ s.row.started_at.strftime('%d %b %Y, %H:%M') }} UTC · {{ s.total }} finding(s)</div>
    <div class="bar">
      {% for sev in ("critical", "high", "medium", "low", "info") %}
        {% if s.counts[sev] %}<span class="bar-seg {{ sev }}" style="width: {{ s.percents[sev] }}%"></span>{% endif %}
      {% endfor %}
    </div>
  </div>
  <div class="badges">
    {% for sev in ("critical", "high", "medium", "low", "info") %}
      {% if s.counts[sev] %}<span class="badge {{ sev }}">{{ s.counts[sev] }} {{ sev }}</span>{% endif %}
    {% endfor %}
    {% if not s.total %}<span class="badge none">no findings</span>{% endif %}
  </div>
  <span class="chev">&rarr;</span>
</a>
{% endfor %}
{% else %}
<div class="card empty">No scans yet — paste a URL or GitHub reference above, or use the CLI (<code>vibetest scan</code> / <code>vibetest scan-repo</code>).</div>
{% endif %}
"""

DETAIL_BODY = """
<a class="back" href="/">&larr; All scans</a>

<section class="card detail-head">
  <div class="left">
    <h1>{{ row.target_url }}</h1>
    <div class="muted">{{ row.started_at.strftime('%d %b %Y, %H:%M') }} UTC · scan {{ row.scan_id[:10] }}</div>
    <div class="chips">
      <span class="chip kind">{{ kind }}</span>
      {% for t in tech %}<span class="chip">{{ t }}</span>{% endfor %}
    </div>
    <div class="chips">
      {% for sev in ("critical", "high", "medium", "low", "info") %}
        {% if summary[sev] %}<span class="badge {{ sev }}">{{ summary[sev] }} {{ sev }}</span>{% endif %}
      {% endfor %}
      {% if not summary.total %}<span class="badge none">no findings</span>{% endif %}
    </div>
  </div>
  <div class="actions">
    <a class="btn" href="/scan/{{ row.scan_id }}/report">Open full report</a>
    <button class="btn secondary" id="pdf-btn"
            data-href="/scan/{{ row.scan_id }}/report.pdf"
            data-report-href="/scan/{{ row.scan_id }}/report"
            data-filename="vibetest-report-{{ row.scan_id[:8] }}.pdf">Download PDF</button>
    <div id="pdf-hint" class="muted hidden">PDF export unavailable on this machine — use <strong>Ctrl+P &rarr; Save as PDF</strong> in the opened report tab.</div>
  </div>
</section>

{% for f in findings %}
<article class="card finding {{ f.severity.value }}">
  <div class="finding-head">
    <span class="badge {{ f.severity.value }}">{{ f.severity.value }}</span>
    <h3>{{ f.title }}</h3>
  </div>
  <div class="muted mono">{{ f.category }}{% if f.cwe_id %} · {{ f.cwe_id }}{% endif %}{% if f.owasp_2025 %} · {{ f.owasp_2025 }}{% endif %}</div>
  {% if f.explanation %}<div class="explain">{{ f.explanation }}</div>{% endif %}
  {% if f.evidence %}
  <details>
    <summary>Evidence ({{ f.evidence | length }})</summary>
    {% for ev in f.evidence %}<pre>{{ ev.url }}{% if ev.detail %} — {{ ev.detail }}{% endif %}{% if ev.snippet %}
{{ ev.snippet }}{% endif %}</pre>{% endfor %}
  </details>
  {% endif %}
  {% if f.remediation_hint %}
  <div class="todo"><strong>What to do</strong><p>{{ f.remediation_hint }}</p></div>
  {% endif %}
</article>
{% else %}
<div class="card empty">No findings recorded for this scan.</div>
{% endfor %}
"""
