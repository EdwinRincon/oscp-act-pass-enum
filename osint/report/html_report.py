# osint/report/html_report.py
import html
import os
from pathlib import Path

from osint.report.serialize import stem

CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--mut:#59636e;--line:#d1d9e0;--ok:#1a7f37;--bad:#cf222e;--card:#f6f8fa}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--line:#30363d;--ok:#3fb950;--bad:#f85149;--card:#161b22}}
body{margin:0 auto;max-width:960px;padding:24px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
h1{font-size:1.5rem;margin:.2em 0}h2{font-size:1.15rem;border-bottom:1px solid var(--line);padding-bottom:4px;margin-top:2em}
h3{font-size:1rem;margin:1.4em 0 .2em}.meta,.mut{color:var(--mut);font-size:.85rem}
table{border-collapse:collapse;width:100%;font:13px ui-monospace,Menlo,Consolas,monospace;margin:.5em 0}
th,td{text-align:left;padding:4px 12px 4px 0;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--mut)}.badge{display:inline-block;padding:0 8px;border:1px solid var(--line);border-radius:10px;font-size:.75rem;margin-left:6px;font-weight:400}
.ok{color:var(--ok)}.bad{color:var(--bad)}.facts{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px;margin:0}
.facts dd{margin:0}.box{background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 16px}
code{font:13px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.table-wrap{max-width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}
.table-wrap table{min-width:560px}
@media (max-width:600px){
body{padding:16px}
h1{font-size:1.3rem;overflow-wrap:anywhere}
.facts{grid-template-columns:1fr;gap:0}
.facts dt{margin-top:8px}
.facts dd{overflow-wrap:anywhere}
.box{padding:12px}
}
@media print{body{max-width:none;padding:0}a{color:inherit;text-decoration:none}}
"""
GOOD, BAD = {"open", "present"}, {"closed", "missing", "failed", "exposed"}
LIMITS = (
    "RDAP and WHOIS data is often redacted (GDPR); missing fields are not evidence of absence.",
    "A name in Certificate Transparency logs proves a certificate was issued, not that the host is live.",
    "The web archive has incomplete coverage; no snapshot does not mean the page never existed.",
    "Active modules observe the target at one moment; results can differ by path, region or User-Agent.",
    "Search links are leads. Open them manually and record what you find with its source and date.",
    "Each finding comes from a single source; the tool does not corroborate across sources.",
)


def esc(value):
    return html.escape(str(value), quote=True)


def cell(value):
    text = str(value)
    if text.startswith(("http://", "https://")):
        return f'<a href="{esc(text)}" rel="noopener noreferrer">{esc(text)}</a>'
    css = "ok" if text.lower() in GOOD else "bad" if text.lower() in BAD else ""
    return f'<span class="{css}">{esc(text)}</span>' if css else esc(text)


def table(headers, rows):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell(c)}</td>" for c in row) + "</tr>" for row in rows)
    return (f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
            f"<tbody>{body}</tbody></table></div>")


def key_facts(results):
    ok = {r["id"]: r for r in results if r["status"] == "ok"}
    facts = []
    if "whois" in ok:
        rows = ok["whois"]["rows"]
        fields = {r[0]: r[1] for r in rows}
        facts += [("Registrar", fields.get("registrar", "-")),
                  ("Registered / expires",
                   f'{fields.get("registration", "-")[:10]} / {fields.get("expiration", "-")[:10]}'),
                  ("Nameservers", sum(r[0] == "nameserver" for r in rows))]
    if "crtsh" in ok:
        facts.append(("Hostnames in CT logs", len(ok["crtsh"]["rows"])))
    if "dns" in ok:
        ips = [r[1] for r in ok["dns"]["rows"] if r[0] in ("A", "AAAA")]
        facts.append(("IP addresses", ", ".join(ips) or "-"))
    if "fingerprint" in ok:
        server = next((r[1] for r in ok["fingerprint"]["rows"] if r[0] == "server"), None)
        if server:
            facts.append(("Server banner", server))
    return facts


def module_block(r):
    tag = "lead (no data collected)" if r["kind"] == "lead" else f'{r["confidence"]} confidence'
    out = [f'<h3>{esc(r["name"])}<span class="badge">{esc(r["phase"])}</span>'
           f'<span class="badge">{esc(tag)}</span></h3>',
           f'<p class="meta">Source: {esc(r["source"])} · Collected (UTC): {esc(r["started_at"])} '
           f'· {r["elapsed"]}s · Status: {esc(r["status"])}</p>']
    if r["status"] == "failed":
        out.append(f'<p class="bad">✖ Failed: {esc(r["error"])}</p>')
    elif not r["rows"]:
        out.append('<p class="mut">No data returned. Absence of data is not evidence of absence.</p>')
    else:
        if r["kind"] == "lead":
            out.append('<p class="mut">Search links only; nothing was requested. Open manually.</p>')
        out.append(table(r["headers"], r["rows"]))
    return "\n".join(out)


def render_html(d):
    results = d["results"]
    ok = sum(r["status"] == "ok" for r in results)
    failed = [r for r in results if r["status"] == "failed"]
    facts = "".join(f"<dt class='mut'>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in key_facts(results))
    auth = "Confirmed by operator" if d["authorised"] else "Not required (passive modules only)"
    scope = [("Target", d["target"]), ("Mode", d["mode"]), ("Authorisation", auth),
             ("Operator", d["operator"] or "-"), ("Engagement note", d["note"] or "-"),
             ("Modules", ", ".join(d["modules_selected"])), ("Timeout per request", f'{d["timeout"]}s'),
             ("Environment", f'{d["environment"]["os"]}, Python {d["environment"]["python"]}'),
             ("Run window (UTC)", f'{d["started_at"]} → {d["finished_at"]} ({d["duration"]}s)')]
    limits = "".join(f"<li>{esc(t)}</li>" for t in LIMITS)
    if "security_headers" in d["modules_selected"]:
        limits += ("<li>Security-header presence is not a security score; "
                   "applicability depends on the application and deployment.</li>")
    fails = "".join(f"<li>{esc(r['name'])}: {esc(r['error'])}</li>" for r in failed)
    title = ("HTTP Security Header Check Report" if d["mode"] == "active web configuration"
             else "OSINT Enumeration Report")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}: {esc(d["target"])}</title><style>{CSS}</style></head><body>
<h1>{title}: {esc(d["target"])}</h1>
<p class="meta">Run {esc(d["run_id"])} · {esc(d["finished_at"])} UTC · {esc(d["tool"])} {esc(d["version"])}</p>
<h2>1. Executive summary</h2>
<div class="box"><p>{ok} of {len(results)} modules completed for <strong>{esc(d["target"])}</strong>
({esc(d["mode"])}); {len(failed)} failed. Findings below are source observations at collection time.</p>
<dl class="facts">{facts}</dl></div>
<h2>2. Scope and methodology</h2>{table(["Item", "Value"], scope)}
<p>Passive modules query public third-party sources and send nothing to the target. Active modules
contact the target directly and will appear in its logs. All timestamps are UTC.</p>
<p class="meta">Confidence: <b>High</b> = direct observation or authoritative registry data at collection
time. <b>Moderate</b> = single third-party aggregator, not corroborated. <b>n/a</b> = lead or failed module.</p>
<h2>3. Findings</h2>{"".join(module_block(r) for r in results)}
<h2>4. Limitations and gaps</h2><ul>{limits}</ul>{f"<p>Failed modules:</p><ul>{fails}</ul>" if fails else ""}
<h2>5. Integrity</h2>
<p>{esc(d["integrity"]["algorithm"])} of the JSON report ({esc(d["integrity"]["covers"])}):</p>
<p><code>{esc(d["integrity"]["sha256"])}</code></p></body></html>"""


def write_html(data, out_dir="output") -> Path:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    path = Path(out_dir) / f"{stem(data)}.html"
    path.write_text(render_html(data), encoding="utf-8")
    os.chmod(path, 0o600)
    return path