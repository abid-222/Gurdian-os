/* Tiny floating/tiling window manager: drag, resize, focus, minimise, maximise, tile, Alt+N switching. */
"use strict";
const WM = {
  wins: new Map(), z: 10, order: [],
  alias(name) {
    const m = { proc: "hierarchy", net: "globe", sec: "shield", sys: "activity", log: "file-text", model: "file-search", cfg: "settings", term: "terminal", home: "home" };
    return m[name] || name;
  },
  svg(name) {
    return svgRaw(this.alias(name));
  },

  open(id, opts = {}) {
    if (this.wins.has(id)) { const w = this.wins.get(id); this.restore(id); this.focus(id); return w; }
    const app = G.apps[id];
    if (!app) return;
    const host = $("#windows"), W = host.clientWidth, H = host.clientHeight;
    const n = this.wins.size;
    const w = Math.min(opts.w || app.w || 820, W - 20), h = Math.min(opts.h || app.h || 520, H - 20);
    const win = el("section", { class: "win", style: `left:${Math.max(10, (opts.x ?? 30 + n * 28))}px;top:${Math.max(10, (opts.y ?? 20 + n * 26))}px;width:${w}px;height:${h}px`, dataset: { id }, "aria-label": app.title });
    const ttl = el("div", { class: "ttl" }, app.title(document.body.dataset.host || "host"));
    const actions = el("div", { class: "titlebar-actions" },
      el("button", { class: "wb m", title: "Minimize", "aria-label": "Minimize", onclick: e => { e.stopPropagation(); this.minimize(id); } },
        svgRaw("minimize", { width: "11", height: "11" })
      ),
      el("button", { class: "wb x", title: "Maximize / Restore", "aria-label": "Maximize / Restore", onclick: e => { e.stopPropagation(); this.toggleMax(id); } },
        svgRaw("maximize", { width: "10", height: "10" })
      ),
      el("button", { class: "wb c", title: "Close (Esc)", "aria-label": "Close", onclick: e => { e.stopPropagation(); this.close(id); } },
        svgRaw("x", { width: "11", height: "11" })
      )
    );
    const iconFrame = renderIcon(this.alias(app.icon), "cyan", "xs", "win-titlebar-icon");
    const bar = el("div", { class: "titlebar" }, iconFrame, ttl, actions);
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
      const mv = ev => {
        win.style.left = Math.max(-win.offsetWidth + 80, Math.min(host.clientWidth - 80, ox + ev.clientX - sx)) + "px";
        win.style.top = Math.max(0, Math.min(host.clientHeight - 30, oy + ev.clientY - sy)) + "px";
      };
      const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); bar.style.cursor = ""; };
      addEventListener("mousemove", mv); addEventListener("mouseup", up); e.preventDefault();
    });
  },

  _resize(win, grip) {
    grip.addEventListener("mousedown", e => {
      const sx = e.clientX, sy = e.clientY, ow = win.offsetWidth, oh = win.offsetHeight;
      const mv = ev => {
        win.style.width = Math.max(360, ow + ev.clientX - sx) + "px";
        win.style.height = Math.max(200, oh + ev.clientY - sy) + "px";
      };
      const up = () => { removeEventListener("mousemove", mv); removeEventListener("mouseup", up); };
      addEventListener("mousemove", mv); addEventListener("mouseup", up); e.preventDefault(); e.stopPropagation();
    });
  },

  focus(id) {
    const r = this.wins.get(id); if (!r) return;
    this.wins.forEach(x => x.win.classList.remove("focus"));
    r.win.classList.add("focus"); r.win.style.zIndex = ++this.z; this.order = this.order.filter(i => i !== id).concat(id);
    r.inst && r.inst.onFocus && r.inst.onFocus(); this.render();
  },

  minimize(id) {
    const r = this.wins.get(id); if (!r) return;
    r.min = true; r.win.classList.add("hidden");
    const next = [...this.order].reverse().find(i => i !== id && !this.wins.get(i).min);
    next ? this.focus(next) : this.render();
  },

  restore(id) { const r = this.wins.get(id); if (!r) return; r.min = false; r.win.classList.remove("hidden"); },
  toggleMax(id) { const r = this.wins.get(id); if (r) r.win.classList.toggle("max"); },
  close(id) { const r = this.wins.get(id); if (!r) return; r.inst && r.inst.destroy && r.inst.destroy(); r.win.remove(); this.wins.delete(id); this.order = this.order.filter(i => i !== id); this.render(); },
  toggle(id) {
    const r = this.wins.get(id);
    if (!r) return this.open(id);
    if (r.min) { this.restore(id); this.focus(id); }
    else if (this.order[this.order.length - 1] === id) this.minimize(id);
    else this.focus(id);
  },

  tile() {
    const list = [...this.wins.values()].filter(r => !r.min); if (!list.length) return;
    const host = $("#windows"), W = host.clientWidth, H = host.clientHeight, cols = Math.ceil(Math.sqrt(list.length)), rows = Math.ceil(list.length / cols);
    list.forEach((r, i) => {
      const c = i % cols, ro = Math.floor(i / cols);
      r.win.classList.remove("max");
      Object.assign(r.win.style, {
        left: (c * W / cols + 6) + "px",
        top: (ro * H / rows + 6) + "px",
        width: (W / cols - 12) + "px",
        height: (H / rows - 12) + "px"
      });
    });
  },

  setTitle(id, text) { const r = this.wins.get(id); if (r) r.ttl.textContent = text; },

  render() {
    const ws = $("#workspaces");
    if (ws) {
      clear(ws);
      let i = 0;
      Object.keys(G.apps).forEach(id => {
        const r = this.wins.get(id); if (!r) return; i++;
        const tabBtn = el("button", {
          class: (r.win.classList.contains("focus") && !r.min ? "active " : "") + (r.min ? "min" : ""),
          onclick: () => this.toggle(id),
          title: r.app.name,
          style: "display:inline-flex;align-items:center;gap:6px"
        },
          renderIcon(this.alias(r.app.icon), r.win.classList.contains("focus") && !r.min ? "cyan" : "slate", "xs"),
          el("span", {}, r.app.name)
        );
        ws.append(tabBtn);
      });
    }

    document.querySelectorAll("#dock button[data-app]").forEach(b => {
      b.classList.toggle("on", this.wins.has(b.dataset.app) && !this.wins.get(b.dataset.app).min);
    });

    const t = $("#tmuxL");
    if (t) {
      clear(t);
      if (this.order.length) {
        t.append("Guardian ");
        Object.keys(G.apps).forEach(id => {
          const r = this.wins.get(id); if (!r) return;
          t.append(el("span", { class: r.win.classList.contains("focus") && !r.min ? "cur" : "" }, `${r.app.short} `));
        });
      }
    }
  },

  byIndex(n) { const ids = Object.keys(G.apps).filter(id => this.wins.has(id)); if (ids[n - 1]) this.toggle(ids[n - 1]); },
};
