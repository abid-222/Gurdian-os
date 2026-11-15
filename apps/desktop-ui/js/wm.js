/* Tiny floating/tiling window manager: drag, resize, focus, minimise, maximise, tile, Alt+N switching. */
"use strict";
const WM = {
  wins: new Map(), z: 10, order: [],
  ICON: {
    home: '<path d="M3 11l9-7 9 7v9H3z"/><path d="M9 20v-6h6v6"/>', term: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
    proc: '<path d="M4 6h16M4 12h10M4 18h16"/><circle cx="18" cy="12" r="2"/>', net: '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
    sec: '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M9 12l2 2 4-4"/>', sys: '<path d="M3 17l5-6 4 4 4-8 5 6"/><path d="M3 21h18"/>',
    log: '<path d="M5 4h14v16H5z"/><path d="M8 9h8M8 13h8M8 17h5"/>', model: '<circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/>',
    cfg: '<path d="M4 7h10M18 7h2M4 17h2M10 17h10"/><circle cx="16" cy="7" r="2"/><circle cx="8" cy="17" r="2"/>',
  },
  svg(name) { const s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("viewBox", "0 0 24 24"); s.innerHTML = this.ICON[name] || ""; return s; },

  open(id, opts = {}) {
    if (this.wins.has(id)) { const w = this.wins.get(id); this.restore(id); this.focus(id); return w; }
    const app = G.apps[id];
    const host = $("#windows"), W = host.clientWidth, H = host.clientHeight;
    const n = this.wins.size;
    const w = Math.min(opts.w || app.w || 760, W - 20), h = Math.min(opts.h || app.h || 480, H - 20);
    const win = el("section", { class: "win", style: `left:${Math.max(6, (opts.x ?? 40 + n * 28))}px;top:${Math.max(6, (opts.y ?? 24 + n * 26))}px;width:${w}px;height:${h}px`, dataset: { id }, "aria-label": app.title });
    const ttl = el("div", { class: "ttl" }, app.title(document.body.dataset.host || "host"));
    const bar = el("div", { class: "titlebar" }, el("span", { class: "ico" }, this.svg(app.icon)), ttl,
      el("button", { class: "wb m", title: "Minimise", "aria-label": "Minimise", onclick: e => { e.stopPropagation(); this.minimize(id); } }, "–"),
      el("button", { class: "wb x", title: "Maximise", "aria-label": "Maximise", onclick: e => { e.stopPropagation(); this.toggleMax(id); } }, "□"),
      el("button", { class: "wb c", title: "Close", "aria-label": "Close", onclick: e => { e.stopPropagation(); this.close(id); } }, "×"));
    const body = el("div", { class: "win-body" + (app.flush ? " flush" : "") });
    const grip = el("div", { class: "resize" });
    win.append(bar, body, grip); host.append(win);
    const rec = { id, win, body, ttl, app, min: false, inst: null };
    this.wins.set(id, rec);
    this._drag(win, bar, id); this._resize(win, grip);
    win.addEventListener("mousedown", () => this.focus(id));
    bar.addEventListener("dblclick", () => this.toggleMax(id));
    rec.inst = app.mount(body, rec) || {};
    this.focus(id); this.render(); return rec;
  },
  _drag(win, bar, id) {
    bar.addEventListener("mousedown", e => {
      if (e.target.closest("button") || win.classList.contains("max")) return;
      const sx = e.clientX, sy = e.clientY, ox = win.offsetLeft, oy = win.offsetTop, host = $("#windows");
      bar.style.cursor = "grabbing";
      const mv = ev => { win.style.left = Math.max(-win.offsetWidth + 80, Math.min(host.clientWidth - 80, ox + ev.clientX - sx)) + "px"; win.style.top = Math.max(0, Math.min(host.clientHeight - 30, oy + ev.clientY - sy)) + "px"; };
      const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); bar.style.cursor = ""; };
      addEventListener("mousemove", mv); addEventListener("mouseup", up); e.preventDefault();
    });
  },
  _resize(win, grip) {
    grip.addEventListener("mousedown", e => {
      const sx = e.clientX, sy = e.clientY, ow = win.offsetWidth, oh = win.offsetHeight;
      const mv = ev => { win.style.width = Math.max(340, ow + ev.clientX - sx) + "px"; win.style.height = Math.max(180, oh + ev.clientY - sy) + "px"; };
      const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); };
      addEventListener("mousemove", mv); addEventListener("mouseup", up); e.preventDefault(); e.stopPropagation();
    });
  },
  focus(id) {
    const r = this.wins.get(id); if (!r) return;
    this.wins.forEach(x => x.win.classList.remove("focus"));
    r.win.classList.add("focus"); r.win.style.zIndex = ++this.z; this.order = this.order.filter(i => i !== id).concat(id);
    r.inst.onFocus && r.inst.onFocus(); this.render();
  },
  minimize(id) { const r = this.wins.get(id); r.min = true; r.win.classList.add("hidden"); const next = [...this.order].reverse().find(i => i !== id && !this.wins.get(i).min); next ? this.focus(next) : this.render(); },
  restore(id) { const r = this.wins.get(id); r.min = false; r.win.classList.remove("hidden"); },
  toggleMax(id) { this.wins.get(id).win.classList.toggle("max"); },
  close(id) { const r = this.wins.get(id); if (!r) return; r.inst.destroy && r.inst.destroy(); r.win.remove(); this.wins.delete(id); this.order = this.order.filter(i => i !== id); this.render(); },
  toggle(id) { const r = this.wins.get(id); if (!r) return this.open(id); if (r.min) { this.restore(id); this.focus(id); } else if (this.order[this.order.length - 1] === id) this.minimize(id); else this.focus(id); },
  tile() {
    const list = [...this.wins.values()].filter(r => !r.min); if (!list.length) return;
    const host = $("#windows"), W = host.clientWidth, H = host.clientHeight, cols = Math.ceil(Math.sqrt(list.length)), rows = Math.ceil(list.length / cols);
    list.forEach((r, i) => { const c = i % cols, ro = Math.floor(i / cols); r.win.classList.remove("max"); Object.assign(r.win.style, { left: c * W / cols + "px", top: ro * H / rows + "px", width: W / cols - 2 + "px", height: H / rows - 2 + "px" }); });
  },
  setTitle(id, text) { const r = this.wins.get(id); if (r) r.ttl.textContent = text; },
  render() {
    const ws = $("#workspaces"); clear(ws);
    let i = 0;
    Object.keys(G.apps).forEach(id => { const r = this.wins.get(id); if (!r) return; i++;
      ws.append(el("button", { class: (r.win.classList.contains("focus") && !r.min ? "active " : "") + (r.min ? "min" : ""), onclick: () => this.toggle(id), title: r.app.name }, `${i}:${r.app.short}`)); });
    document.querySelectorAll("#dock button[data-app]").forEach(b => b.classList.toggle("on", this.wins.has(b.dataset.app) && !this.wins.get(b.dataset.app).min));
    const t = $("#tmuxL"); clear(t); let j = 0;
    this.order.length || t.append("[guardian] no windows — press Ctrl+K");
    if (this.order.length) { t.append("[guardian] "); Object.keys(G.apps).forEach(id => { const r = this.wins.get(id); if (!r) return; t.append(el("span", { class: r.win.classList.contains("focus") && !r.min ? "cur" : "" }, `${j++}:${r.app.short}${r.win.classList.contains("focus") ? "*" : r.min ? "-" : ""}`), " "); }); }
  },
  byIndex(n) { const ids = Object.keys(G.apps).filter(id => this.wins.has(id)); if (ids[n - 1]) this.toggle(ids[n - 1]); },
};
