/* Core: DOM helper, API client (token header), websocket, formatting, tiny pub/sub. No frameworks, no network except loopback. */
"use strict";
const G = { token: null, apps: {}, state: { health: null, summary: null, history: [] }, subs: {}, ws: null };

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat()) if (c !== null && c !== undefined && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
  return n;
}
const $ = (s, r = document) => r.querySelector(s);
const clear = n => { while (n.firstChild) n.removeChild(n.firstChild); return n; };

const fmt = {
  bytes(n) { n = +n || 0; const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; while (n >= 1024 && i < 4) { n /= 1024; i++; } return (i ? n.toFixed(1) : n.toFixed(0)) + " " + u[i]; },
  pct(n) { return (n === null || n === undefined) ? "--" : (+n).toFixed(1) + "%"; },
  time(ts) { return ts ? new Date(ts * 1000).toLocaleTimeString([], { hour12: false }) : ""; },
  datetime(ts) { return ts ? new Date(ts * 1000).toLocaleString([], { hour12: false }) : ""; },
  ago(ts) { const s = Math.max(0, Date.now() / 1000 - ts); if (s < 60) return Math.floor(s) + "s ago"; if (s < 3600) return Math.floor(s / 60) + "m ago"; if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago"; },
  dur(s) { s = Math.floor(s); const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60); return (d ? d + "d " : "") + h + "h " + m + "m"; },
  short(s, n = 60) { s = s || ""; return s.length > n ? s.slice(0, n - 1) + "…" : s; },
};

/* Severity: colour AND glyph AND text — modern humanized badges */
const SEV = {
  informational: { glyph: "ℹ", label: "Info", cls: "sev-info" },
  low: { glyph: "●", label: "Low Risk", cls: "sev-low" },
  medium: { glyph: "▲", label: "Medium", cls: "sev-med" },
  high: { glyph: "⚠️", label: "High Risk", cls: "sev-high" },
  critical: { glyph: "🚨", label: "Critical", cls: "sev-crit" },
};
const sevChip = s => {
  const d = SEV[s] || SEV.informational;
  return el("span", { class: "badge " + d.cls }, el("span", { class: "badge-dot" }), d.label);
};

async function api(path, opts = {}) {
  const o = { method: opts.method || "GET", headers: { "X-Guardian-Token": G.token } };
  if (opts.body !== undefined) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(opts.body); }
  const r = await fetch("/api/v1" + path, o);
  if (r.status === 401) { showLock(); throw new Error("unauthorised"); }
  if (!r.ok) { let m = r.statusText; try { m = (await r.json()).detail || m; } catch (e) { } throw new Error(typeof m === "string" ? m : JSON.stringify(m)); }
  return r.json();
}

function on(evt, fn) { (G.subs[evt] ||= new Set()).add(fn); return () => G.subs[evt].delete(fn); }
function emit(evt, data) { (G.subs[evt] || []).forEach(f => { try { f(data); } catch (e) { console.error(e); } }); }

function toast(msg, kind = "info") {
  const t = el("div", { class: "toast t-" + kind, role: "status" }, msg);
  $("#toasts").append(t); setTimeout(() => t.remove(), 5200);
}

function connectWS() {
  const ws = new WebSocket(`ws://${location.host}/api/v1/ws`);
  G.ws = ws;
  ws.onopen = () => ws.send(JSON.stringify({ token: G.token }));
  ws.onmessage = m => {
    const d = JSON.parse(m.data);
    if (d.type === "incident") { toast(`${(SEV[d.data.severity] || SEV.low).glyph} ${d.data.title}`, d.data.severity); }
    emit(d.type, d.data);
  };
  ws.onclose = () => setTimeout(() => G.token && connectWS(), 3000);
}

function showLock() { $("#shell").hidden = true; $("#lock").hidden = false; }

/* Reusable table: columns [{k, label, w, render, cls}] */
function table(cols, rows, { onRow, rowCls, selected } = {}) {
  const t = el("table", { class: "tbl" });
  t.append(el("thead", {}, el("tr", {}, cols.map(c => el("th", { style: c.w ? `width:${c.w}` : null, class: c.cls }, c.label)))));
  const tb = el("tbody");
  for (const r of rows) {
    const tr = el("tr", { class: [rowCls ? rowCls(r) : "", selected && selected(r) ? "sel" : ""].join(" "), tabindex: onRow ? "0" : null });
    for (const c of cols) { const v = c.render ? c.render(r) : r[c.k]; tr.append(el("td", { class: c.cls }, v === undefined || v === null ? "" : v)); }
    if (onRow) { tr.addEventListener("click", () => onRow(r)); tr.addEventListener("keydown", e => { if (e.key === "Enter") onRow(r); }); }
    tb.append(tr);
  }
  t.append(tb); return t;
}

function bar(pct, width = 20, label = "") {
  const p = Math.max(0, Math.min(100, pct || 0));
  const cls = p > 85 ? "bar-hi" : p > 60 ? "bar-mid" : "bar-ok";
  return el("div", { class: "progress-pill", title: label || fmt.pct(p) },
    el("div", { class: "progress-track" },
      el("div", { class: "progress-fill " + cls, style: `width:${p}%` })
    ),
    el("span", { class: "progress-val" }, fmt.pct(p))
  );
}

function spark(values, w = 220, h = 38, max = 100) {
  const c = el("canvas", { width: w * 2, height: h * 2, style: `width:${w}px;height:${h}px` });
  const g = c.getContext("2d"); g.scale(2, 2);
  const css = getComputedStyle(document.documentElement);
  g.strokeStyle = css.getPropertyValue("--accent").trim() || "#2dd4bf"; g.lineWidth = 1.4; g.beginPath();
  values.forEach((v, i) => { const x = i / Math.max(1, values.length - 1) * (w - 2) + 1, y = h - 2 - (Math.min(v, max) / max) * (h - 4); i ? g.lineTo(x, y) : g.moveTo(x, y); });
  g.stroke();
  g.lineTo(w - 1, h); g.lineTo(1, h); g.closePath(); g.globalAlpha = .12; g.fillStyle = g.strokeStyle; g.fill();
  return c;
}

function kv(rows) { return el("dl", { class: "kv" }, rows.filter(Boolean).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v === undefined || v === null || v === "" ? "—" : v)])); }

// Guarded, user-initiated response (terminate / suspend / resume / quarantine). Typing the process name is the confirmation.
async function respond(action, target, name, after) {
  try {
    const pv = await api("/actions/preview", { method: "POST", body: { action, target } });
    const typed = prompt(`${action.toUpperCase()} ${name}?\n\n${pv.impact}\n\nType the process name to confirm:  ${name}`);
    if (typed === null) return;
    const r = await api("/actions/execute", { method: "POST", body: { action, target, confirm_name: typed } });
    toast(r.detail, r.ok ? undefined : "high");
    if (after) after();
  } catch (e) { toast(e.message, "high"); }
}
