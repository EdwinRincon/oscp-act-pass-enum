// osint/web/static/app.js
"use strict";
const $ = (s) => document.querySelector(s);
const DOMAIN_RE = /^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$/i;
const validTarget = (value) => DOMAIN_RE.test(value) ||
  value.split(".").length === 4 && value.split(".").every((part) =>
    /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
const GOOD = new Set(["open", "present"]);
const BAD = new Set(["closed", "missing", "failed", "exposed"]);
const filters = { q: "", phase: "all", status: "all", conf: "all" };
let report = null, jobId = "";

const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "text") n.textContent = v; else if (k === "class") n.className = v; else n.setAttribute(k, v);
  }
  n.append(...kids);
  return n;
};

async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function cellNode(value) {
  const text = String(value);
  if (/^https?:\/\//i.test(text)) return el("a", { href: text, target: "_blank", rel: "noopener noreferrer", text });
  const low = text.toLowerCase();
  if (GOOD.has(low)) return el("span", { class: "ok", text: `● ${text}` });
  if (BAD.has(low)) return el("span", { class: "bad", text: `✖ ${text}` });
  return document.createTextNode(text);
}

function card(r, rows) {
  const tag = r.kind === "lead" ? "lead (no data collected)" : `${r.confidence} confidence`;
  const box = el("article", { class: "card" },
    el("h3", {}, r.name, el("span", { class: "badge", text: r.phase }), el("span", { class: "badge", text: tag })),
    el("p", { class: "meta", text: `Source: ${r.source} · Collected (UTC): ${r.started_at} · ${r.elapsed}s · ${r.status}` }));
  if (r.status === "failed") box.append(el("p", { class: "bad", text: `✖ Failed: ${r.error}` }));
  else if (r.status === "skipped") box.append(el("p", { class: "mut", text: `Skipped: ${r.error}` }));
  else if (!rows.length) box.append(el("p", { class: "mut", text: "No data returned. Absence of data is not evidence of absence." }));
  else {
    const head = el("tr", {}, ...r.headers.map((h) => el("th", { text: h })));
    const body = rows.map((row) => el("tr", {}, ...row.map((c) => el("td", {}, cellNode(c)))));
    box.append(el("table", {}, el("thead", {}, head), el("tbody", {}, ...body)));
  }
  return box;
}

function renderResults() {
  const wrap = $("#cards");
  wrap.replaceChildren();
  const q = filters.q.toLowerCase();
  let shown = 0;
  for (const r of report.results) {
    if (filters.phase !== "all" && r.phase !== filters.phase) continue;
    if (filters.status !== "all" && r.status !== filters.status) continue;
    if (filters.conf !== "all" && r.confidence !== filters.conf) continue;
    const rows = q ? r.rows.filter((row) => row.join(" ").toLowerCase().includes(q)) : r.rows;
    if (q && !rows.length) continue;
    wrap.append(card(r, rows));
    shown++;
  }
  $("#empty").hidden = shown > 0;
}

function renderReport() {
  const ok = report.results.filter((r) => r.status === "ok").length;
  const failed = report.results.filter((r) => r.status === "failed").length;
  const skipped = report.results.filter((r) => r.status === "skipped").length;
  const stat = (label, value) => el("div", {}, el("b", { text: String(value) }), el("span", { class: "mut", text: label }));
  const dl = (ext) => el("a", { class: "btn sec", href: `/api/scan/${jobId}/report.${ext}`,
    download: `${report.target}_${report.run_id}.${ext}`, text: `Download ${ext.toUpperCase()}` });
  const copy = el("button", { type: "button", class: "sec", text: "Copy SHA-256" });
  copy.addEventListener("click", () => navigator.clipboard.writeText(report.integrity.sha256));
  $("#summary").replaceChildren(
    el("div", { class: "stats" }, stat("target", report.target), stat("modules ok", ok),
      stat("failed", failed), stat("skipped", skipped), stat("seconds", report.duration)),
    el("div", { class: "actions" }, dl("html"), dl("json"), copy),
    el("p", { class: "meta" }, `Run ${report.run_id} · ${report.finished_at} UTC · SHA-256 `,
      el("code", { text: report.integrity.sha256 })));
  $("#results").hidden = false;
  renderResults();
}

function renderProgress(j) {
  $("#bar").max = j.total;
  $("#bar").value = j.progress.length;
  $("#status").textContent = j.status === "running"
    ? `Running: ${j.current} (${j.progress.length}/${j.total})` : `Finished (${j.progress.length}/${j.total})`;
  $("#done").replaceChildren(...j.progress.map((p) => {
    const symbol = p.status === "ok" ? "●" : p.status === "skipped" ? "○" : "✖";
    return el("li", { class: p.status, text: `${symbol} ${p.name} (${p.elapsed}s)` });
  }));
}

async function poll(id) {
  for (;;) {
    const j = await api(`/api/scan/${id}`);
    renderProgress(j);
    if (j.status === "done") { report = j.report; jobId = id; return renderReport(); }
    if (j.status === "error") throw new Error(j.error);
    await new Promise((r) => setTimeout(r, 700));
  }
}

async function onSubmit(e) {
  e.preventDefault();
  const err = $("#form-err");
  err.textContent = "";
  const domain = $("#domain").value.trim().toLowerCase();
  const chosen = [...document.querySelectorAll("#modules input[data-id]:checked")].map((b) => b.dataset.id);
  if (!validTarget(domain)) { err.textContent = "Enter a valid domain or IPv4 address."; return; }
  if (!chosen.length) { err.textContent = "Select at least one module."; return; }
  $("#run").disabled = true;
  $("#results").hidden = true;
  $("#progress").hidden = false;
  try {
    const job = await api("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, modules: chosen, timeout: Number($("#timeout").value),
        user_agent: $("#user-agent").value,
        headers: $("#headers").value.split(/\r?\n/).filter((line) => line.trim()),
        rustscan_ports: $("#rustscan-ports").value,
        rustscan_timeout: Number($("#rustscan-timeout").value),
        operator: $("#operator").value, note: $("#note").value, authorised: $("#auth").checked }) });
    await poll(job.id);
  } catch (ex) {
    err.textContent = ex.message;
    $("#progress").hidden = true;
  } finally {
    $("#run").disabled = false;
  }
}

async function init() {
  const info = await api("/api/modules");
  $("#ver").textContent = `v${info.version}`;
  $("#timeout").min = info.http.min_timeout;
  $("#timeout").max = info.http.max_timeout;
  $("#user-agent").value = info.http.default_user_agent;
  $("#rustscan-ports").value = info.http.default_rustscan_ports;
  $("#rustscan-timeout").min = info.http.min_rustscan_timeout;
  $("#rustscan-timeout").max = info.http.max_rustscan_timeout;
  $("#rustscan-timeout").value = info.http.default_rustscan_timeout;
  for (const m of info.modules) {
    const box = el("input", { type: "checkbox", "data-id": m.id, "data-phase": m.phase,
      "data-available": String(m.available), "data-auto-active": String(m.auto_when_active) });
    box.checked = m.phase === "passive" && m.available && !m.optional;
    box.disabled = m.phase === "active" || !m.available;
    const availability = m.available ? "" : " · not installed";
    if (m.id === "searchsploit") box.dataset.searchsploit = "true";
    $(`#mod-${m.phase}`).append(el("label", { class: "check" }, box,
      el("span", {}, m.title, el("small", { class: "mut", text: ` · ${m.source}${availability}` }))));
  }
  const searchsploit = $('input[data-searchsploit="true"]');
  const syncExploitSearch = () => {
    const activeSelected = [...document.querySelectorAll('input[data-phase="active"]:checked')].length > 0;
    if (!searchsploit || searchsploit.dataset.available !== "true") return;
    if (activeSelected) {
      searchsploit.checked = true;
      searchsploit.dataset.autoChecked = "true";
    } else if (searchsploit.dataset.autoChecked === "true") {
      searchsploit.checked = false;
      delete searchsploit.dataset.autoChecked;
    }
  };
  document.querySelectorAll('input[data-phase="active"]').forEach((box) =>
    box.addEventListener("change", syncExploitSearch));
  $("#auth").addEventListener("change", (e) => {
    document.querySelectorAll('input[data-phase="active"]').forEach((b) => {
      b.disabled = !e.target.checked || b.dataset.available === "false";
      if (!e.target.checked) b.checked = false;
    });
    syncExploitSearch();
  });
  $("#scan-form").addEventListener("submit", onSubmit);
  for (const [id, key] of [["q", "q"], ["f-phase", "phase"], ["f-status", "status"], ["f-conf", "conf"]]) {
    $(`#${id}`).addEventListener("input", (e) => { filters[key] = e.target.value; if (report) renderResults(); });
  }
}
init();