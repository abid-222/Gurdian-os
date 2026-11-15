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

/* ==========================================================================
   Professional Vector Icon System (Linear / Raycast / macOS Style)
   ========================================================================== */
const ICONS = {
  "home": '<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
  "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  "shield-check": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
  "shield-alert": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  "shield-off": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  "terminal": '<polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/>',
  "cpu": '<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>',
  "memory": '<rect x="2" y="5" width="20" height="14" rx="2"/><line x1="6" y1="9" x2="6" y2="15"/><line x1="10" y1="9" x2="10" y2="15"/><line x1="14" y1="9" x2="14" y2="15"/><line x1="18" y1="9" x2="18" y2="15"/>',
  "hard-drive": '<line x1="22" y1="12" x2="2" y2="12"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z"/><line x1="6" y1="16" x2="6.01" y2="16"/><line x1="10" y1="16" x2="10.01" y2="16"/>',
  "hierarchy": '<rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M10 6.5h4"/><path d="M6.5 10v4"/><path d="M17.5 10v4"/>',
  "tree": '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>',
  "network": '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  "globe": '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  "activity": '<polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>',
  "zap": '<polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>',
  "layers": '<polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/>',
  "lock": '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
  "unlock": '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/>',
  "key": '<circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/>',
  "file-search": '<path d="M4 22h14a2 2 0 0 0 2-2V7.5L14.5 2H6a2 2 0 0 0-2 2v4"/><polyline points="14 2 14 8 20 8"/><circle cx="8" cy="15" r="3"/><path d="m10.5 17.5 2.5 2.5"/>',
  "file-text": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
  "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>',
  "alert-triangle": '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
  "alert-circle": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>',
  "info": '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>',
  "check": '<polyline points="20 6 9 17 4 12"/>',
  "x": '<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>',
  "chevron-down": '<polyline points="6 9 12 15 18 9"/>',
  "chevron-right": '<polyline points="9 18 15 12 9 6"/>',
  "play": '<polygon points="5 3 19 12 5 21 5 3"/>',
  "pause": '<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>',
  "clock": '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
  "refresh-cw": '<path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/>',
  "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>',
  "box": '<path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>'
};

function svgRaw(name, extraAttrs = {}) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  for (const [k, v] of Object.entries(extraAttrs)) s.setAttribute(k, v);
  s.innerHTML = ICONS[name] || ICONS["shield"];
  return s;
}

function renderIcon(name, colorVariant = "cyan", sizeVariant = "md", extraCls = "") {
  const frame = el("span", { class: `icon-frame ${sizeVariant} ${colorVariant} ${extraCls}`.trim() });
  frame.append(svgRaw(name));
  return frame;
}

/* Severity: Crisp Vector Badges — No Text Emojis */
const SEV = {
  informational: { icon: "info", label: "Info", color: "cyan", cls: "sev-info" },
  low: { icon: "shield-check", label: "Low Risk", color: "emerald", cls: "sev-low" },
  medium: { icon: "alert-circle", label: "Medium", color: "amber", cls: "sev-med" },
  high: { icon: "alert-triangle", label: "High Risk", color: "rose", cls: "sev-high" },
  critical: { icon: "shield-alert", label: "Critical", color: "rose", cls: "sev-crit" },
};

const sevChip = s => {
  const d = SEV[s] || SEV.informational;
  const chip = el("span", { class: "badge " + d.cls });
  chip.append(renderIcon(d.icon, d.color, "xs", "badge-icon-frame"), el("span", { class: "badge-text" }, d.label));
  return chip;
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

function showLock() {
  const s = $("#shell"), l = $("#lock");
  if (s) s.hidden = true;
  if (l) l.hidden = false;
  setTimeout(() => {
    const inp = $("#tokenIn");
    if (inp) inp.focus();
  }, 50);
}

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
