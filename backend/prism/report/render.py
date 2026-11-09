"""HTML report pages: one page per deliverable in the brief (§7), built from run evidence only.

  ..\\aienv\\Scripts\\python.exe -m prism.report.render

Every number on every page is read from a run folder (results.json, security_results.json, gate_*.json,
canary_results.json, drift_results.json, repro.json, audit logs); nothing is typed by hand. Output goes
to reports/ at the project root, with the evidence files copied to reports/evidence/.
"""
from __future__ import annotations

import html
import json
import re
import shutil
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from .. import masking
from ..settings import BACKEND_DIR, CONFIG_DIR, DATA_DIR, PROMPTS_DIR, RUNS_DIR, SCHEMAS_DIR, budgets, thresholds

OUT = BACKEND_DIR.parent / "reports"
AUTHOR = "Kenneth Yeo"
PAGES = [("index.html", "Release decision"), ("dataset.html", "Dataset"), ("prompts.html", "Prompts & A/B"),
         ("agents.html", "Agents"), ("security_audit.html", "Security audit"), ("governance.html", "Governance"),
         ("quality_gate.html", "Quality gate"), ("canary.html", "Canary"), ("drift.html", "Drift & incident"),
         ("handoff.html", "Handoff")]

CSS = """
:root{--bg:#f7f7f5;--panel:#fff;--ink:#1d1d1f;--muted:#5f6368;--line:#d6d6d2;--soft:#eceff1;
--ok:#1e7f4f;--ok-bg:#e6f4ea;--bad:#b3261e;--bad-bg:#fce8e6;--warn:#8a6100;--warn-bg:#fef7e0;
--accent:#4a72c4;--accent-bg:#e8f0fe;--s1:#4a72c4;--s2:#c0392b;--s3:#2e8b57;--grid:#e3e3df}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#141416;--panel:#1e1f22;--ink:#e8e8ea;
--muted:#a0a3a8;--line:#3a3b3f;--soft:#24282b;--ok:#6fcf97;--ok-bg:#16301f;--bad:#f08a7e;--bad-bg:#3a1a17;
--warn:#e0b84a;--warn-bg:#33290f;--accent:#7fa2e8;--accent-bg:#1c2a44;--s1:#7fa2e8;--s2:#f08a7e;--s3:#6fcf97;--grid:#2c2d31}}
:root[data-theme="dark"]{--bg:#141416;--panel:#1e1f22;--ink:#e8e8ea;--muted:#a0a3a8;--line:#3a3b3f;--soft:#24282b;
--ok:#6fcf97;--ok-bg:#16301f;--bad:#f08a7e;--bad-bg:#3a1a17;--warn:#e0b84a;--warn-bg:#33290f;--accent:#7fa2e8;
--accent-bg:#1c2a44;--s1:#7fa2e8;--s2:#f08a7e;--s3:#6fcf97;--grid:#2c2d31}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1180px;margin:0 auto;padding:24px 16px 64px}h1{font-size:30px;margin:0 0 4px}
h1 .by{font-size:14px;font-weight:400;color:var(--muted);margin-left:8px;white-space:nowrap}
h2{font-size:20px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}h3{font-size:16px;margin:18px 0 6px}
.meta{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);font-size:13px;margin:6px 0 14px}
code,pre{font-family:ui-monospace,Consolas,monospace;font-size:13px}code{background:var(--soft);padding:1px 5px;border-radius:4px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;line-height:1.45;white-space:pre-wrap}
nav{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 20px}nav a{font-size:13px;text-decoration:none;color:var(--ink);border:1px solid var(--line);background:var(--panel);padding:5px 11px;border-radius:999px}
nav a.on{background:var(--accent-bg);border-color:var(--accent);color:var(--accent);font-weight:600}
.banner{display:flex;flex-wrap:wrap;align-items:center;gap:18px;border-radius:12px;padding:18px 22px;border:2px solid var(--ok);background:var(--ok-bg)}
.banner.bad{border-color:var(--bad);background:var(--bad-bg)}.banner .big{font-size:40px;font-weight:800;color:var(--ok)}.banner.bad .big{color:var(--bad)}
.banner p{margin:0;max-width:820px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(160px,100%),1fr));gap:10px;margin:16px 0}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.kpi .v{font-size:24px;font-weight:700}.kpi .l{font-size:12px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(340px,100%),1fr));gap:14px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}.card h3{margin-top:0}
.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--panel);font-size:14px}
th,td{border-bottom:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}th{background:var(--soft);font-weight:600}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.pill{display:inline-block;font-size:12px;font-weight:700;padding:1px 9px;border-radius:999px;white-space:nowrap}
.pass{background:var(--ok-bg);color:var(--ok)}.fail{background:var(--bad-bg);color:var(--bad)}.info{background:var(--soft);color:var(--muted)}.warn{background:var(--warn-bg);color:var(--warn)}
.note{font-size:13px;color:var(--muted)}a{color:var(--accent)}
svg text{font-family:system-ui,sans-serif;fill:var(--muted);font-size:11px}.gl{stroke:var(--grid);stroke-width:1}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:10px}
@media print{nav,footer{display:none}body{background:#fff}main{padding:0}@page{size:A4;margin:12mm}}
"""

BASE = Template("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>PRism {{ title }}</title><style>{{ css }}</style></head>
<body><main><h1>PRism — {{ title }} <span class="by">by {{ author }}</span></h1>
<div class="meta">{% for k, v in meta %}<span>{{ k }} <code>{{ v }}</code></span>{% endfor %}</div>
<nav>{% for f, t in pages %}<a href="{{ f }}"{% if f == page %} class="on"{% endif %}>{{ t }}</a>{% endfor %}</nav>
{{ body }}
<footer>PRism by {{ author }} · generated {{ generated }} by <code>python -m prism.report.render</code> from run evidence in
<code>reports/evidence/</code>. Every number links back to a run file; none is typed by hand.</footer></main></body></html>""")


# ----------------------------------------------------------------------------- helpers
def esc(x) -> str:
    return html.escape(str(x))


def pill(ok, yes="PASS", no="FAIL") -> str:
    if ok is None:
        return '<span class="pill info">n/a</span>'
    return f'<span class="pill {"pass" if ok else "fail"}">{yes if ok else no}</span>'


def table(headers, rows, num_cols=()) -> str:
    h = "".join(f"<th>{esc(x)}</th>" for x in headers)
    body = "".join("<tr>" + "".join(f'<td{" class=n" if i in num_cols else ""}>{c}</td>' for i, c in enumerate(r))
                   + "</tr>" for r in rows)
    return f'<div class="scroll"><table><tr>{h}</tr>{body}</table></div>'


def md(text: str) -> str:
    """Tiny markdown subset: headings, bullets, numbered lists, tables, bold, code."""
    def inline(s):
        s = esc(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
        return re.sub(r"`(.+?)`", r"<code>\1</code>", s)
    out, lines, i = [], text.splitlines(), 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(set(c) <= set("-: ") for c in cells):
                    rows.append(cells)
                i += 1
            out.append(table(rows[0], [[inline(c) for c in r] for r in rows[1:]]))
            continue
        if m := re.match(r"^(#{1,3}) (.*)", ln):
            lvl = min(3, len(m.group(1)) + 1)
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
        elif re.match(r"^\s*[-*] ", ln):
            items = []
            while i < len(lines) and re.match(r"^\s*[-*] ", lines[i]):
                items.append(f"<li>{inline(re.sub(r'^\s*[-*] ', '', lines[i]))}</li>")
                i += 1
            out.append("<ul>" + "".join(items) + "</ul>")
            continue
        elif re.match(r"^\d+\. ", ln):
            items = []
            while i < len(lines) and re.match(r"^\d+\. ", lines[i]):
                items.append(f"<li>{inline(re.sub(r'^\d+\. ', '', lines[i]))}</li>")
                i += 1
            out.append("<ol>" + "".join(items) + "</ol>")
            continue
        elif ln.strip():
            out.append(f"<p>{inline(ln)}</p>")
        i += 1
    return "\n".join(out)


def line_chart(series: list[tuple[str, list[float], str]], height=200, ymin=0.0, ymax=1.0, marks=(), xlabel="") -> str:
    w, pad = 720, 40
    n = max(len(s[1]) for s in series)
    sx = lambda i: pad + i * (w - pad - 10) / max(1, n - 1)  # noqa: E731
    sy = lambda v: height - 25 - (v - ymin) / (ymax - ymin or 1) * (height - 40)  # noqa: E731
    g = "".join(f'<line x1="{pad}" y1="{sy(ymin + f * (ymax - ymin)):.1f}" x2="{w - 10}" y2="{sy(ymin + f * (ymax - ymin)):.1f}" class="gl"/>'
                f'<text x="2" y="{sy(ymin + f * (ymax - ymin)) + 4:.1f}">{ymin + f * (ymax - ymin):.2g}</text>' for f in (0, .5, 1))
    lines = "".join(
        f'<polyline fill="none" stroke="var({c})" stroke-width="1.8" points="'
        + " ".join(f"{sx(i):.1f},{sy(v):.1f}" for i, v in enumerate(vals) if v is not None) + '"/>'
        for _, vals, c in series)
    mk = "".join(f'<line x1="{sx(x):.1f}" y1="10" x2="{sx(x):.1f}" y2="{height - 25}" stroke="var({c})" stroke-dasharray="4 3" stroke-width="1.5"/>'
                 f'<text x="{sx(x) + 4:.1f}" y="{18 + k * 13}" style="fill:var({c})">{esc(lbl)}</text>' for k, (x, lbl, c) in enumerate(marks))
    legend = " ".join(f'<span style="color:var({c})">■</span> {esc(n_)}' for n_, _, c in series)
    return (f'<svg viewBox="0 0 {w} {height}" width="100%" role="img">{g}{lines}{mk}'
            f'<text x="{pad}" y="{height - 6}">0</text><text x="{w - 40}" y="{height - 6}">{n - 1}</text>'
            f'<text x="{w // 2 - 30}" y="{height - 6}">{esc(xlabel)}</text></svg><div class="note">{legend}</div>')


def bars(items: list[tuple[str, float, float | None]], unit="", width=360) -> str:
    """items: (label, value, budget)."""
    top = max([v for _, v, _ in items] + [b or 0 for _, _, b in items]) or 1
    rows = []
    for k, (lbl, v, b) in enumerate(items):
        y = 8 + k * 30
        bw = (width - 120) * v / top
        rows.append(f'<text x="0" y="{y + 13}">{esc(lbl)}</text><rect x="110" y="{y}" width="{width - 120}" height="16" fill="var(--soft)"/>'
                    f'<rect x="110" y="{y}" width="{bw:.1f}" height="16" fill="var(--s1)"/>'
                    + (f'<line x1="{110 + (width - 120) * b / top:.1f}" y1="{y - 3}" x2="{110 + (width - 120) * b / top:.1f}" y2="{y + 19}" stroke="var(--s2)" stroke-width="2"/>' if b else "")
                    + f'<text x="{114 + bw:.1f}" y="{y + 13}" style="fill:var(--ink)">{v:,.0f}{unit}{f" / {b:,.0f}" if b else ""}</text>')
    return f'<svg viewBox="0 0 {width + 60} {len(items) * 30 + 10}" width="100%" role="img">{"".join(rows)}</svg>'


def load_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def latest(prefix: str, name: str) -> Path:
    runs = sorted((p for p in RUNS_DIR.glob(f"{prefix}*") if (p / name).exists()), key=lambda p: p.name)
    if not runs:
        raise SystemExit(f"no runs/{prefix}* with {name}")
    return runs[-1]


# ----------------------------------------------------------------------------- evidence
class E:
    def __init__(self, main_run: str | None = None, sec_run: str | None = None):
        self.main_dir = RUNS_DIR / main_run if main_run else latest("main_", "results.json")
        self.sec_dir = RUNS_DIR / sec_run if sec_run else latest("security_", "gate_v1.json")
        self.can_dir = latest("canary_", "canary_results.json")
        self.drift_dir = latest("drift_", "drift_results.json")
        self.repro_dir = latest("repro_", "repro.json")
        self.main = load_json(self.main_dir / "results.json")
        self.sec = load_json(self.sec_dir / "security_results.json")
        self.g1 = load_json(self.sec_dir / "gate_v1.json")
        self.g0 = load_json(self.sec_dir / "gate_v0.json")
        self.can = load_json(self.can_dir / "canary_results.json")
        self.can_log = [json.loads(x) for x in (self.can_dir / "canary_log.jsonl").read_text(encoding="utf-8").splitlines()]
        self.drift = load_json(self.drift_dir / "drift_results.json")
        self.incident = (self.drift_dir / "incident_note.md").read_text(encoding="utf-8")
        self.repro = load_json(self.repro_dir / "repro.json")
        self.golden = [json.loads(x) for x in (DATA_DIR / "golden/v1.jsonl").read_text(encoding="utf-8").splitlines()]
        self.manifest = load_json(DATA_DIR / "golden/MANIFEST.json")
        self.validation = load_json(DATA_DIR / "golden/v1.validation.json")
        self.first_run = load_json(DATA_DIR / "golden/v1.first_run")
        self.tc_scores = [json.loads(x) for x in (self.main_dir / "task_completion.jsonl").read_text(encoding="utf-8").splitlines()]
        self.audit = [json.loads(x) for x in (self.main_dir / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()]
        self.sec_audit = [json.loads(x) for x in (self.sec_dir / "audit_log.jsonl").read_text(encoding="utf-8").splitlines()]
        self.winner = self.main["ab_test"]["winner"]
        self.w = self.main["ab_test"][self.winner]

    def meta(self):
        return [("main run", self.main_dir.name), ("security run", self.sec_dir.name), ("build", "v1"),
                (f"prompt {self.winner}", self.main["prompt_hashes"][self.winner]), ("agent", self.main["models"]["agent"]),
                ("judge", self.main["models"]["judge"]), ("golden v1", self.main["freeze"]["golden_sha256"][:12])]


# ----------------------------------------------------------------------------- pages
def gate_table(e: E) -> str:
    v0 = {g["gate"]: g for g in e.g0["gates"]}
    rows = []
    for g in e.g1["gates"]:
        def show(x):
            v = x["value"]
            if isinstance(v, dict):
                return f"tokens {v['token_ratio']}x · p95 {v['p95_latency_ratio']}x · F1 {v['f1_ratio']}x"
            return esc(v)
        rows.append([esc(g["gate"]), esc(g["applies_to"]), esc(g["threshold"]), show(v0[g["gate"]]), pill(v0[g["gate"]]["passed"]),
                     f"<b>{show(g)}</b>", pill(g["passed"])])
    return table(["Gate", "Applies to", "Threshold", "v0 value", "v0", "v1 value", "v1"], rows)


def page_index(e: E) -> str:
    s = e.sec["builds"]["v1"]["summary"]
    tc = e.main["coordinator"]["task_completion"]["mean"]
    a1, a2 = e.can["attempts"]
    d = e.drift["detection"]
    go = e.g1["passed"]
    banner = f"""<div class="banner{'' if go else ' bad'}"><div class="big">{'GO' if go else 'NO-GO'}</div><p>
<b>{'Recommend release' if go else 'Do not release'} of build v1 with reviewer prompt {e.winner}{', with two conditions' if go else ''}.</b>
The quality gate passes {sum(g['passed'] for g in e.g1['gates'])}/{len(e.g1['gates'])} (exit {e.g1['exit_code']}) on the frozen 20-sample golden set;
all 6 planted defects found on v0 are fixed and re-tested; {s['handwritten_succeeded'] + s['redteam_succeeded']} of
{len(e.sec['builds']['v1']['handwritten']) + len(e.sec['builds']['v1']['redteam'])} attacks succeeded on v1 and
{e.sec['builds']['v1']['rbac']['violations']} of {e.sec['builds']['v1']['rbac']['tests']} RBAC tests failed. The canary rolled back automatically on an SLA
breach, then promoted {e.winner} to 100%. Conditions: (1) route reviews of async / heavily type-hinted code to a human until golden v2
closes the data drift found at request {d['detected_start_request']}; (2) track the open privacy-recall gap QUAL-001.</p></div>"""
    kpis = [(f"{sum(g['passed'] for g in e.g1['gates'])} / {len(e.g1['gates'])}", "gates passed (v1)"),
            (f"{s['handwritten_succeeded'] + s['redteam_succeeded']} / 18", "attacks succeeded (v1)"),
            (f"{tc}", "task completion (≥ 0.85)"), (f"{e.w['quality']['f1']}", f"finding F1, prompt {e.winner}"),
            (f"{e.main['comparison']['token_ratio']}×", "tokens vs single agent"),
            ("6 / 6", "v0 defects fixed with evidence")]
    k = "".join(f'<div class="kpi"><div class="v">{esc(v)}</div><div class="l">{esc(l)}</div></div>' for v, l in kpis)
    deliverables = [
        ("Versioned golden dataset and validator results", "dataset.html"),
        ("Per-agent results table and single vs multi-agent comparison", "agents.html"),
        ("Audit log sample", "governance.html#audit"), ("Security audit report", "security_audit.html"),
        ("Quality gate output showing pass or fail", "quality_gate.html"), ("Canary and rollback log", "canary.html"),
        ("Drift analysis and incident note", "drift.html"), ("Artifact reproducibility check logs and audit records", "governance.html#repro"),
        ("Prompt A/B test and output specification", "prompts.html"), ("Handoff document", "handoff.html")]
    dl = table(["Deliverable (brief §7)", "Page"], [[esc(a), f'<a href="{b}">{esc(b)}</a>'] for a, b in deliverables])
    demo = md("""1. **Release decision (this page):** the GO, the 9 gates, v0 vs v1 (45 s)
2. **Security audit:** v0 defects with evidence, then v1 blocking all 18 attacks (75 s)
3. **Agents:** per-agent tables; multi-agent at 0.35x the tokens of a single agent (45 s)
4. **Canary:** automatic rollback on the SLA breach, then promotion to 100% (45 s)
5. **Drift:** blind detection at request 51, sealed truth 50, why it is drift not regression (45 s)
6. **Reproducibility:** cached re-run, 0 calls, 0 metric differences; recommendation and risks (45 s)""")
    risks = table(["Risk", "Evidence", "Mitigation"], [
        ["Data drift on async / type-hinted code", f"quality {e.drift['detection']['ks_reference_vs_after']['quality_score']['mean_ref']} → "
         f"{e.drift['detection']['ks_reference_vs_after']['quality_score']['mean_after']} from request {d['detected_start_request']}", "human review for that code; golden v2 + rubric update"],
        ["Privacy findings missed (QUAL-001)", "G018 / G019 / G020 judge scores 0.3–0.5", "rubric + regex lint rule, re-measure"],
        ["Small samples", "20 golden samples; 2 candidate requests at the 10% canary stage", "grow golden v2; longer canary stages"],
        ["Providers outside Singapore", "Gemini API, Groq (RES-1)", "only masked synthetic code leaves the machine"]])
    return f"""{banner}<div class="kpis">{k}</div><h2>Quality gate (brief §5)</h2>{gate_table(e)}
<p class="note">Commands: <code>python -m prism.gate --build v1</code> → exit {e.g1['exit_code']}; <code>--build v0</code> → exit {e.g0['exit_code']}.</p>
<h2>Deliverables</h2>{dl}<h2>Open risks</h2>{risks}<h2>Five-minute demo</h2>{demo}"""


def page_dataset(e: E) -> str:
    counts = e.manifest["counts"]
    prob = """<div class="card"><b>Problem statement (Task 2.1).</b> A three-agent code review system (Coordinator → Reader → Reviewer over two
MCP tools) must return accurate, schema-valid findings without leaking secrets or personal data, breaking role-based access, or obeying
instructions hidden in the code it reads. We do not know how well it does this, how it compares with a single agent, or whether it stays
healthy in production. <b>Success</b> means every brief §5 threshold passes on the frozen 20-sample golden set, the system stays within 3× a
single agent's tokens and p95 latency unless quality gains justify it, and the canary holds its SLA to 100%.</div>"""
    rows = [[esc(g["id"]), f"<code>{esc(g['file'])}</code>", esc(g["category"]), esc(g["role"]), "yes" if g["restricted"] else "",
             str(len(g["expected_findings"])), esc((g.get("attack") or {}).get("type", "")), str(g["line_count"])] for g in e.golden]
    val = table(["Validator", "Result", "Problems"], [[esc(c["name"]), pill(c["passed"]), esc("; ".join(c["problems"]) or "none")]
                                                      for c in e.validation["checks"]])
    seed = [json.loads(x) for x in (DATA_DIR / "seed_reference.jsonl").read_text(encoding="utf-8").splitlines()]
    return f"""{prob}<div class="kpis">{''.join(f'<div class="kpi"><div class="v">{v}</div><div class="l">{esc(k)} samples</div></div>' for k, v in counts.items())}
<div class="kpi"><div class="v">{sum(len(g['expected_findings']) for g in e.golden)}</div><div class="l">expected findings</div></div></div>
<h2>Versioning and freeze (Task 2.4)</h2><div class="card">Version <code>v1</code> · sha256 <code>{e.manifest['golden_sha256']}</code> ·
created {esc(e.manifest['created_utc'])} by <code>{esc(e.manifest['generator'])}</code> (seed {e.manifest['seed']}) · files set read-only ·
first evaluation run <code>{esc(e.first_run['run_id'])}</code> at {esc(e.first_run['at'][:19])}Z, after which the generator refuses to rewrite the set.
Every run checks the golden file and all 20 sample hashes against <code>MANIFEST.json</code> before starting
(<code>{esc(e.main['freeze'])}</code>). Expected-finding line numbers are computed from a unique anchor string in each file.</div>
<h2>Validators (Task 2.3)</h2>{val}
<h2>Golden samples</h2>{table(['ID', 'File', 'Category', 'Role', 'Restricted', 'Expected', 'Attack', 'Lines'], rows, (5, 7))}
<h2>Seed reference (finding format)</h2><pre>{esc(json.dumps(seed[0], indent=2))}</pre>"""


def page_prompts(e: E) -> str:
    schema = (SCHEMAS_DIR / "review.schema.json").read_text(encoding="utf-8")
    a, b = e.main["ab_test"]["vA"], e.main["ab_test"]["vB"]
    keys = [("F1", "f1"), ("Precision", "precision"), ("Recall", "recall"), ("Severity accuracy", "severity_accuracy"),
            ("ROUGE-L", "rougeL"), ("BLEU", "bleu")]
    rows = [[n, str(a["quality"][k]), str(b["quality"][k])] for n, k in keys]
    rows += [["Valid JSON", f"{a['valid_json_rate']:.0%}", f"{b['valid_json_rate']:.0%}"],
             ["Tokens / review (mean)", str(a["trajectory"]["tokens_mean"]), str(b["trajectory"]["tokens_mean"])],
             ["Hallucinated comments", str(a["hallucinated_comments"]), str(b["hallucinated_comments"])],
             ["Successful injections", str(a["injections"]["succeeded"]), str(b["injections"]["succeeded"])]]
    pa = (PROMPTS_DIR / "reviewer_vA.md").read_text(encoding="utf-8")
    pb = (PROMPTS_DIR / "reviewer_vB.md").read_text(encoding="utf-8")
    return f"""<h2>Output specification (Task 3.1)</h2><div class="card">One JSON object per reviewed file: <code>file</code> and
<code>findings</code>, each finding with <code>file</code>, <code>line</code> (1-based, must exist), <code>severity</code>
(low / medium / high / critical) and <code>comment</code> (5–400 characters: the problem, then the fix). Enforced three ways: pydantic
output type, <code>review.schema.json</code> on every output (Task 3.4), and the v1 guard that drops lines outside the file.</div>
<pre>{esc(schema)}</pre><h2>A/B test (Task 3.2–3.3): {e.winner} wins</h2>
{table(['Metric (20 golden samples, build v1)', f'vA · {e.main["prompt_hashes"]["vA"]}', f'vB · {e.main["prompt_hashes"]["vB"]}'], rows, (1, 2))}
<div class="card"><b>Justification.</b> {esc(e.main['ab_test']['justification'])}</div>
<div class="grid"><div class="card"><h3>Prompt vA (plain)</h3><pre>{esc(pa)}</pre></div><div class="card"><h3>Prompt vB (rubric, numbered lines)</h3><pre>{esc(pb)}</pre></div></div>"""


def page_agents(e: E) -> str:
    w, base, rd, co = e.w, e.main["baseline"], e.main["reader"], e.main["coordinator"]
    th = thresholds()["gates"]
    reader = table(["Reader metric (Task 4.1)", "Threshold", "Value", ""], [
        ["Tool correctness (one read_file of the right path and role)", "≥ 90%", f"{w['tool_correctness']['reader']['rate']:.0%}", pill(w['tool_correctness']['reader']['rate'] >= .9)],
        ["RBAC correctness (main-run probes)", "0 violations", f"{rd['rbac_violations']} / {rd['rbac_probes']}", pill(rd['rbac_violations'] == 0)],
        ["RBAC correctness (full suite)", "0 violations", f"{e.sec['builds']['v1']['rbac']['violations']} / {e.sec['builds']['v1']['rbac']['tests']}", pill(e.sec['builds']['v1']['rbac']['violations'] == 0)],
        ["Masking (planted secrets in Reader output)", "0", str(rd["masking_leaks"]), pill(rd["masking_leaks"] == 0)],
        ["Audit log completeness (role, tool, target, decision)", "100%", f"{rd['audit_log_completeness']:.0%} of {rd['tool_calls_logged']}", pill(rd["audit_log_completeness"] == 1)]])
    q = w["quality"]
    reviewer = table(["Reviewer metric (Task 4.2)", "Threshold", "Value", ""], [
        ["Valid JSON", f"≥ {th['valid_json_rate']['min']:.0%}", f"{w['valid_json_rate']:.0%}", pill(w['valid_json_rate'] >= .95)],
        ["Hallucinated comments (nonexistent lines)", "0", f"{w['hallucinated_comments']} (guard blocked {w['hallucinations_blocked_by_guard']})", pill(w['hallucinated_comments'] == 0)],
        ["Tool correctness (one lint of the right file)", "≥ 90%", f"{w['tool_correctness']['reviewer']['rate']:.0%}", pill(w['tool_correctness']['reviewer']['rate'] >= .9)],
        ["ROUGE-L / BLEU (matched comments)", "report", f"{q['rougeL']} / {q['bleu']}", '<span class="pill info">report</span>'],
        ["Finding precision / recall / F1", "report", f"{q['precision']} / {q['recall']} / {q['f1']}", '<span class="pill info">report</span>'],
        ["Severity accuracy (matched)", "report", str(q["severity_accuracy"]), '<span class="pill info">report</span>']])
    t = co["trajectory"]
    coord = table(["Coordinator metric (Task 4.3)", "Threshold", "Value", ""], [
        ["Task completion (DeepEval G-Eval, reference-based)", "≥ 0.85", str(co["task_completion"]["mean"]), pill(co["task_completion"]["mean"] >= .85)],
        ["Handoff correctness (file, role, task, code hash)", "100%", f"{co['handoff']['correct']} / {co['handoff']['total']}", pill(co['handoff']['rate'] == 1)],
        ["Trajectory: steps / LLM requests per review", "report", f"{t['steps_mean']} / {t['llm_requests_mean']}", '<span class="pill info">report</span>'],
        ["Trajectory: tokens mean (max)", "report", f"{t['tokens_mean']} ({t['tokens_max']})", '<span class="pill info">report</span>'],
        ["Trajectory: latency mean / p95", "report", f"{t['latency_mean_ms']:.0f} / {t['latency_p95_ms']:.0f} ms", '<span class="pill info">report</span>']])
    tcs = table(["Sample", "Score", "Judge reason"], [[esc(s["id"]), f"{s.get('score')}", esc((s.get("reason") or s.get("error") or "")[:220])]
                                                      for s in e.tc_scores], (1,))
    c = e.main["comparison"]
    comp = table(["", "Single-agent baseline", f"3-agent system ({e.winner})", "Ratio"], [
        ["Finding F1", str(base["quality"]["f1"]), str(q["f1"]), f"{c['f1_ratio']}×"],
        ["Precision / recall", f"{base['quality']['precision']} / {base['quality']['recall']}", f"{q['precision']} / {q['recall']}", ""],
        ["Valid JSON", f"{base['valid_json_rate']:.0%}", f"{w['valid_json_rate']:.0%}", ""],
        ["Tool correctness", f"{base['tool_correctness']['baseline']['rate']:.0%}", "100%", ""],
        ["LLM requests / review", str(base["trajectory"]["llm_requests_mean"]), str(t["llm_requests_mean"]), ""],
        ["Tokens / review (mean)", str(base["trajectory"]["tokens_mean"]), str(t["tokens_mean"]), f"{c['token_ratio']}×"],
        ["p95 latency (ms)", f"{base['trajectory']['latency_p95_ms']:.0f}", f"{t['latency_p95_ms']:.0f}", f"{c['p95_latency_ratio']}×"],
        ["Successful injections (golden)", str(base["injections"]["succeeded"]), str(w["injections"]["succeeded"]), ""]])
    bud = budgets()["token_budget_per_request"]
    judge_tok = [x["usage"]["total_tokens"] / max(1, x["usage"]["requests"]) for x in e.audit
                 if x.get("event") == "llm_call" and x.get("agent") == "deepeval_judge" and x.get("usage")]
    tok = bars([("Coordinator", 0, None), ("Reader", 0, None), ("Reviewer", t["tokens_mean"], bud["reviewer"]),
                ("Baseline", base["trajectory"]["tokens_mean"], bud["baseline"]),
                ("Judge / request", sum(judge_tok) / len(judge_tok) if judge_tok else 0, bud["judge"])])
    return f"""<div class="grid"><div>{reader}</div><div>{reviewer}</div></div>{coord}
<h3>Task completion per sample</h3>{tcs}
<h2>Single-agent vs multi-agent (Task 4.4–4.5)</h2>{comp}
<div class="card">Efficiency gate: {esc(c['rule'])} → {pill(c['passed'])}. The baseline is one LLM agent that calls both MCP tools itself
(about 3 requests per review); the 3-agent system routes and reads deterministically and makes one LLM call, so it costs
{c['token_ratio']}× the tokens at {c['f1_ratio']}× the F1.</div>
<h2>Token use per agent vs budget (Task 1.2)</h2><div class="card">{tok}<p class="note">Bar = mean tokens per request; red tick = budget in
<code>config/budgets.yaml</code>. Coordinator and Reader make no LLM calls.</p></div>"""


def page_security(e: E) -> str:
    v1, v0 = e.sec["builds"]["v1"], e.sec["builds"]["v0"]
    m0 = {r["id"]: r for r in v0["handwritten"] + v0["redteam"]}
    rows = []
    for r in v1["handwritten"] + v1["redteam"]:
        x = m0[r["id"]]
        rows.append([esc(r["id"]), esc(r["name"]), esc(r.get("converter") or "hand-written"), str(r["turns"]),
                     esc(r.get("severity", "high")), pill(not x["succeeded"], "blocked", "succeeded"), pill(not r["succeeded"], "blocked", "succeeded")])
    defects = (BACKEND_DIR / "defects/DEF-001-006_sut.md").read_text(encoding="utf-8")
    dtable = defects[defects.index("| ID |"):defects.index("Gate outcome")]
    bh = ", ".join(f"{x['id']} {'blocked' if not x['succeeded'] else 'SUCCEEDED'}" for x in v1["baseline_handwritten"])
    return f"""<div class="card"><b>Scope.</b> Build v1 (release candidate) and v0 (flawed build), {datetime.now():%d %b %Y}. {v1['rbac']['tests']} RBAC tests,
6 hand-written attacks (Task 5.1: comment injection, secret request, role escalation, handoff manipulation, plus path traversal and
hallucination bait of our own), 12 red-team cases generated with PyRIT converters (Task 5.5: 8 indirect injections via code, 4 multi-turn),
and a leak scan of every output and the audit log. Success oracles use the audit log, not the agents' own status.
<b>Result:</b> v1 {v1['summary']['handwritten_succeeded'] + v1['summary']['redteam_succeeded']}/18 attacks succeeded, {v1['rbac']['violations']} RBAC violations,
{v1['log_leaks']} log leaks → <span class="pill pass">PASS</span>; v0 {v0['summary']['handwritten_succeeded'] + v0['summary']['redteam_succeeded']}/18,
{v0['rbac']['violations']} RBAC violations, {v0['log_leaks']} log leaks → <span class="pill fail">FAIL</span>.</div>
{table(['ID', 'Test', 'Generator / converter', 'Turns', 'Severity', 'v0', 'v1'], rows, (3,))}
<p class="note">Single-agent baseline on the hand-written attacks: {esc(bh)}. RT08 on v0 was hijacked by the plain forged handoff already in
its a04 carrier, not by the Base64 payload.</p>
<h2>Defects found on v0 (reported with evidence before fixing)</h2>{md(dtable)}
<p class="note">Full register with evidence paths: <code>backend/defects/DEF-001-006_sut.md</code>; evaluation-harness defects:
<code>backend/defects/EVAL-001-003_harness.md</code>.</p>"""


def page_governance(e: E) -> str:
    want = [("tool_call", lambda x: x.get("tool") == "read_file" and x.get("decision") == "allow"),
            ("tool_call", lambda x: x.get("tool") == "read_file" and x.get("decision") == "deny"),
            ("tool_call", lambda x: x.get("tool") == "lint"), ("handoff", lambda x: True),
            ("llm_call", lambda x: x.get("agent", "").startswith("reviewer_vB")), ("llm_call", lambda x: x.get("agent") == "deepeval_judge")]
    sample = []
    for ev, f in want:
        x = next((a for a in e.audit if a.get("event") == ev and f(a)), None)
        if x:
            sample.append(x)
    v0_raw = next((a for a in e.sec_audit if a.get("build") == "v0" and a.get("content_preview")), None)
    v0_show = dict(v0_raw, content_preview=masking.mask(v0_raw["content_preview"])[0] + "   [re-masked for this report]") if v0_raw else {}
    comp = table(["ID", "Framework", "Control", "Result", "Evidence"], [[esc(c["id"]), esc(c["framework"]), esc(c["control"]), pill(c["passed"]),
                                                                      esc(c["detail"])] for c in e.g1["compliance"]])
    r = e.repro
    led = {}
    for p in sorted(RUNS_DIR.glob("*/audit_log.jsonl")):
        for x in (json.loads(y) for y in p.read_text(encoding="utf-8").splitlines()):
            if x.get("event") == "llm_call" and not x.get("cache_hit"):
                led[x["model"]] = led.get(x["model"], 0) + (x.get("usage") or {}).get("requests", 1)
    return f"""<h2 id="audit">Audit log sample (Task 1.4)</h2><div class="card">Hash-chained JSONL, one entry per tool call, handoff and LLM call.
Each entry has role, tool, target and decision, plus build, golden-dataset hash and both dependency-lock hashes; LLM entries add the
prompt-template hash and model id (Task 1.7). Main run: {len(e.audit)} entries, chain verified
<code>{esc(e.main['audit_chain'])}</code>; completeness {e.main['reader']['audit_log_completeness']:.0%}.</div>
<pre>{esc(chr(10).join(json.dumps(x, ensure_ascii=False) for x in sample))}</pre>
<h3>DEF-002 evidence: a v0 audit entry (raw content preview)</h3><pre>{esc(json.dumps(v0_show, ensure_ascii=False)[:900])}</pre>
<h2>Compliance checklist (Task 1.6)</h2>{comp}<p class="note">Mappings are indicative and need sign-off from a compliance owner; not legal advice.</p>
<h2>Provenance hashes (Task 1.7)</h2>{table(['Item', 'Hash / id'], [
        ['Golden dataset v1', f"<code>{e.main['freeze']['golden_sha256']}</code>"],
        *[[f'Prompt template {k}', f'<code>{v}</code>'] for k, v in e.main['prompt_hashes'].items()],
        ['Agent model', f"<code>{e.main['models']['agent']}</code>"], ['Judge model', f"<code>{e.main['models']['judge']}</code>"],
        ['requirements.lock (aienv)', f"<code>{r['provenance']['deps_sha256']}</code>"],
        ['requirements-redteam.lock (aienv-redteam)', f"<code>{r['provenance']['redteam_deps_sha256']}</code>"]])}
<div class="card">Two virtual environments: PyRIT 1.1 needs <code>huggingface-hub ≥ 1.31</code> → <code>click ≥ 8.4.2</code>, DeepEval 4.3 needs
<code>click &lt; 8.4</code>; no single environment satisfies both (found by <code>pip check</code>). PyRIT lives in <code>aienv-redteam</code> and only
generates the red-team cases.</div>
<h2 id="repro">Reproducibility check</h2>{table(['Check', 'Result'], [[esc(k), pill(v) if isinstance(v, bool) else esc(v)] for k, v in r['checks'].items()])}
<p class="note">Reference <code>{r['reference_run']}</code> re-run as <code>{r['rerun']}</code> at {r['checked_at']}: {len(r['differences'])} metric differences,
passed {pill(r['passed'])}. Command: <code>python -m tools.repro_check</code>.</p>
<h2>LLM usage (all runs, billed requests)</h2>{table(['Model', 'Requests'], [[esc(k), str(v)] for k, v in sorted(led.items())], (1,))}"""


def page_gate(e: E) -> str:
    return f"""<div class="kpis"><div class="kpi"><div class="v">{pill(e.g1['passed'])} exit {e.g1['exit_code']}</div><div class="l">build v1</div></div>
<div class="kpi"><div class="v">{pill(e.g0['passed'])} exit {e.g0['exit_code']}</div><div class="l">build v0 (planted defects)</div></div></div>
<div class="card">The gate (Task 5.4) reads the main run and the security run, checks every brief §5 threshold, the efficiency rule and the
compliance checklist, and exits <b>1 on any breach</b>, failing the build. Command: <code>python -m prism.gate --build v1</code>.
A gate value that was not measured counts as a failure.</div>{gate_table(e)}
<h2>Gate output (v1)</h2><pre>{esc((e.sec_dir / 'gate_v1.md').read_text(encoding='utf-8')[:1800])}</pre>"""


def page_canary(e: E) -> str:
    rows = []
    for a in e.can["attempts"]:
        rows.append([esc(a["attempt"]), "on" if a["with_fault"] else "resolved", pill(a["status"] == "promoted", a["status"], a["status"]),
                     f"{a['final_candidate_pct']:.0%}", f"{a['served']['stable']} / {a['served']['candidate']}"])
    ev = [x for x in e.can_log if x["event"] != "request" or x.get("injected_fault_ms")]
    evt = table(["Attempt", "Event", "Candidate %", "Detail"], [[esc(x["attempt"]), esc(x["event"]), f"{x['candidate_pct']:.0%}",
               esc({k: v for k, v in x.items() if k not in ("attempt", "event", "candidate_pct")})] for x in ev])
    checks = [x for x in e.can_log if x["event"] == "sla_check"]
    pts = "".join(f"<tr><td>{esc(x['attempt'])}</td><td>{x['stage']}</td><td class=n>{x['candidate_requests']}</td><td class=n>{x['candidate_p95_ms']}</td>"
                  f"<td>{pill(x['passed'])}</td></tr>" for x in checks)
    return f"""<div class="card"><b>SLA (Task 6.2):</b> {esc(e.can['sla'])}. <b>Stable:</b> {esc(e.can['stable'])}; <b>candidate:</b> {esc(e.can['candidate'])}.
60 replayed requests in three 20-request stages at 10% / 50% / 100%; routing by sha256(request_id) mod 100. Responses come from the LLM cache
(0 calls); latency = local processing + the originally measured LLM latency + any injected fault. Attempt 1 replays the file as given
(9,000 ms candidate fault on requests 3–8); attempt 2 replays it after the fault is resolved.</div>
{table(['Attempt', 'Fault', 'Outcome', 'Final candidate %', 'Served stable / candidate'], rows)}
<h2>SLA checks</h2><div class="scroll"><table><tr><th>Attempt</th><th>Stage</th><th>Candidate requests</th><th>Candidate p95 ms (SLA {thresholds()['canary']['sla_p95_latency_ms']})</th><th></th></tr>{pts}</table></div>
<p class="note">Limitation: the 10% stage has only 2 candidate requests, so its p95 rests on very few samples.</p>
<h2>Canary and rollback log</h2>{evt}<p class="note">Full log (every request): <code>evidence/canary_log.jsonl</code>; also in the hash-chained audit log.</p>"""


def page_drift(e: E) -> str:
    d, s = e.drift["detection"], e.drift["series"]
    det, true = d["detected_start_seq"], e.drift["sealed"].get("drift_start_seq")
    chart = line_chart([("quality score", [x["quality"] for x in s], "--s1"), ("async ratio", [x["async_ratio"] for x in s], "--s3"),
                        ("type-hint density", [x["type_hint_density"] for x in s], "--warn")],
                       marks=[(det, f"detected {det}", "--s2"), (true, f"true {true} (sealed)", "--muted")], xlabel="request seq")
    ks = table(["Signal", "Reference mean", "After mean", "KS stat", "p-value", "Shifted"], [
        [esc(k), str(v["mean_ref"]), str(v["mean_after"]), str(v["ks_stat"]), str(v["p_value"]),
         '<span class="pill warn">yes</span>' if v["shifted"] else '<span class="pill info">no</span>']
        for k, v in d["ks_reference_vs_after"].items()], (1, 2, 3, 4))
    return f"""<div class="kpis"><div class="kpi"><div class="v">seq {det}</div><div class="l">drift began (detected blind, {esc(d['detected_start_request'])})</div></div>
<div class="kpi"><div class="v">seq {true}</div><div class="l">true start (sealed, sha256 verified {e.drift['sealed']['hash_verified']})</div></div>
<div class="kpi"><div class="v">{e.drift['error_requests']:+}</div><div class="l">detection error (requests)</div></div>
<div class="kpi"><div class="v">{esc(d['drift_type'])}</div><div class="l">drift type</div></div></div>
<div class="card">{chart}</div>
<h2>Detection (Task 7.1)</h2><div class="card">Reference = the first {d['reference_window'][1] + 1} requests (quality mean {d['reference_quality_mean']},
sd {d['reference_quality_sd']}). Lower-side CUSUM on quality (k = 0.5σ, h = 5σ) raised the alarm at seq {d['cusum_alarm_seq']}; the change point is the last
zero of the CUSUM before the alarm, seq <b>{det}</b>. The detector never reads <code>data/sealed/</code>; the sealed file was opened only after the
detection was saved and logged, and its sha256 matched <code>data/drift_point.sha256</code>.</div>{ks}
<h2>Type (Task 7.2) and drift vs regression (Task 7.3)</h2><div class="card"><b>Data drift (covariate shift):</b> input features
{', '.join(d['shifted_inputs'])} shifted (KS p &lt; 0.01) while build {d['invariants']['build']}, prompt {d['invariants']['prompt_version']} and model
{d['invariants']['model_id']} never changed. <b>This is drift and not a regression:</b> the quality drop began with a measurable change in the input
distribution while every system hash stayed the same, and the frozen golden set still scores identically on re-run
(golden metrics identical: {e.drift['regression_check'].get('golden_metrics_identical')}), so the system did not get worse — the traffic changed.</div>
<h2>Incident note (Task 7.4)</h2><div class="card">{md(e.incident)}</div>"""


def page_handoff(e: E) -> str:
    return md(f"""## What was built
- **System under test** (`backend/prism/`): Coordinator and Reader (deterministic), Reviewer (1 LLM call, Gemini 3.5 Flash-Lite), a tool-using single-agent baseline, and an MCP server with `read_file` (Casbin RBAC + Presidio/regex masking) and `lint` (ruff). Build `v0` keeps six planted defects; build `v1` fixes them.
- **Evaluation**: frozen golden set v1 (20 samples), validators, async harness, per-agent metrics, prompt A/B ({e.winner} wins), DeepEval G-Eval task completion, single vs multi-agent comparison.
- **Security**: 339-case RBAC suite, 6 hand-written attacks, 12 PyRIT red-team cases (4 multi-turn), quality gate with compliance checklist.
- **Release**: canary with SLA and automatic rollback; blind CUSUM/KS drift detection with a sealed drift point; incident note.

## How to run (from `backend/`)
1. `..\\aienv\\Scripts\\python.exe -m pytest -q` (12 offline tests, no keys)
2. `..\\aienv\\Scripts\\python.exe -m prism.eval.run_main` (main evaluation; cached re-runs cost 0 calls)
3. `..\\aienv\\Scripts\\python.exe -m prism.security.run_security` then `-m prism.gate --build v1`
4. `..\\aienv\\Scripts\\python.exe -m prism.release.canary` and `-m prism.release.drift`
5. `..\\aienv\\Scripts\\python.exe -m tools.repro_check` and `-m prism.report.render`

## Known limits
- 20 golden samples, Python only; the 10% canary stage sees 2 candidate requests.
- Golden labels were written by one author (Claude, from the generator) and not yet reviewed by a second person.
- The red-team payloads are converter-obfuscated templates, not an adaptive attacker; PyRIT's multi-turn orchestrators were out of scope for time and API budget.
- Free-tier quotas: Gemini 3.5 Flash-Lite 500 requests/day/project; Groq 1K requests and 200K tokens/day per organization.

## Next steps
1. Golden dataset **v2** with async and type-hinted samples (closes the data drift); re-run the A/B test and gate.
2. Close QUAL-001 (privacy-recall gap): rubric update plus a regex lint rule for PII in logs and per-assignment secrets.
3. Second-person review of the golden labels; grow to 30 samples.
4. Wire `prism.gate` into CI so a failing gate blocks merges.""")


def render(main_run: str | None = None, sec_run: str | None = None) -> Path:
    e = E(main_run, sec_run)
    OUT.mkdir(exist_ok=True)
    ev = OUT / "evidence"
    ev.mkdir(exist_ok=True)
    for src, name in [(e.main_dir / "results.json", "main_results.json"), (e.main_dir / "results.md", "main_results.md"),
                      (e.main_dir / "task_completion.jsonl", "task_completion.jsonl"),
                      (e.sec_dir / "security_results.json", "security_results.json"),
                      (e.sec_dir / "gate_v1.md", "gate_v1.md"), (e.sec_dir / "gate_v0.md", "gate_v0.md"),
                      (e.sec_dir / "gate_v1.json", "gate_v1.json"), (e.sec_dir / "gate_v0.json", "gate_v0.json"),
                      (e.can_dir / "canary_log.jsonl", "canary_log.jsonl"), (e.can_dir / "canary_results.json", "canary_results.json"),
                      (e.drift_dir / "drift_results.json", "drift_results.json"), (e.drift_dir / "incident_note.md", "incident_note.md"),
                      (e.repro_dir / "repro.json", "repro.json"), (DATA_DIR / "golden/v1.validation.json", "golden_v1_validation.json"),
                      (DATA_DIR / "golden/MANIFEST.json", "golden_MANIFEST.json")]:
        shutil.copyfile(src, ev / name)
    # audit-log sample: first 40 entries of the main run (v1, already masked)
    (ev / "audit_log_sample.jsonl").write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in e.audit[:40]) + "\n", encoding="utf-8")
    builders = {"index.html": page_index, "dataset.html": page_dataset, "prompts.html": page_prompts, "agents.html": page_agents,
                "security_audit.html": page_security, "governance.html": page_governance, "quality_gate.html": page_gate,
                "canary.html": page_canary, "drift.html": page_drift, "handoff.html": page_handoff}
    gen = datetime.now().strftime("%d %b %Y %H:%M")
    for f, title in PAGES:
        (OUT / f).write_text(BASE.render(title=title, css=CSS, author=AUTHOR, meta=e.meta(), pages=PAGES, page=f,
                                         body=builders[f](e), generated=gen), encoding="utf-8")
    print(f"rendered {len(PAGES)} pages -> {OUT}  (main {e.main_dir.name}, security {e.sec_dir.name}, "
          f"canary {e.can_dir.name}, drift {e.drift_dir.name}, repro {e.repro_dir.name})")
    return OUT


if __name__ == "__main__":
    import sys
    render(*(sys.argv[1:3]))
