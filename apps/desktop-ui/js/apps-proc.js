"use strict";
function download(name, obj) {
  const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" })), download: name });
  document.body.append(a); a.click(); a.remove();
}

G.apps.processes = {
  name: "Process Center", short: "procs", icon: "proc", w: 1040, h: 620, flush: true, title: h => `Guardian OS — Process Center (${h})`,
  mount(body) {
    const st = { sort: "rss", order: "desc", q: "", tree: true, sel: null, items: [], alive: true };
    const sorts = ["rss", "cpu", "pid", "name", "start_ts"];
    const search = el("input", { placeholder: "F3 search name / pid / path", style: "width:240px", oninput: e => { st.q = e.target.value; load(); } });
    const bars = el("span"), tbl = el("div", { style: "flex:1;overflow:auto;min-height:0" }), detail = el("div", { class: "pad", style: "overflow:auto;border-top:1px solid var(--line);max-height:42%;display:none" });
    const sortSel = el("select", { "aria-label": "sort", onchange: e => { st.sort = e.target.value; load(); } }, sorts.map(s => el("option", { value: s }, s)));
    const treeBtn = el("button", { style: "font-weight:600", onclick: () => toggleTree() });
    function updateTreeBtn() {
      treeBtn.textContent = st.tree ? "🌳 Process Tree: ON (F5)" : "📋 Table View (F5)";
      if (st.tree) treeBtn.classList.add("st-ok"); else treeBtn.classList.remove("st-ok");
    }
    function toggleTree() {
      st.tree = !st.tree;
      updateTreeBtn();
      load();
    }
    updateTreeBtn();
    const menubar = el("div", { class: "menubar" }, search, el("label", {}, "sort ", sortSel), treeBtn, el("span", { class: "sp" }), bars);
    const fkeys = el("div", { class: "fkeys" },
      ...[["F3", "Search", () => search.focus()], ["F5", "Tree", toggleTree], ["F6", "Sort", () => { st.sort = sorts[(sorts.indexOf(st.sort) + 1) % sorts.length]; sortSel.value = st.sort; load(); }],
        ["F9", "Terminate", () => { const r = st.rows && st.rows.find(x => x.key === st.sel); st.sel && respond("terminate", st.sel, r ? r.name : st.sel); }], ["F10", "Close", () => WM.close("processes")]].map(([k, l, f]) => el("button", { onclick: f }, el("b", {}, k), l)));
    body.append(menubar, tbl, detail, fkeys); body.tabIndex = 0;
    body.addEventListener("keydown", e => { const m = { F3: 0, F5: 1, F6: 2, F9: 3, F10: 4 }[e.key]; if (m !== undefined) { e.preventDefault(); fkeys.children[m].click(); } });

    function order(items) {
      if (!st.tree) return items.map(p => ({ p, prefix: "", childCount: 0 }));
      const byKey = new Map(items.map(p => [p.key, p]));
      const byPid = new Map(items.map(p => [p.pid, p]));
      const kids = new Map();

      items.forEach(p => {
        let parentKey = null;
        if (p.parent_key && byKey.has(p.parent_key)) {
          parentKey = p.parent_key;
        } else if (p.ppid !== undefined && p.ppid !== null && byPid.has(p.ppid)) {
          const parent = byPid.get(p.ppid);
          if (parent && parent.key !== p.key) {
            parentKey = parent.key;
          }
        }
        (kids.get(parentKey) || kids.set(parentKey, []).get(parentKey)).push(p);
      });

      const out = [];
      const visited = new Set();
      const walk = (p, pre, last, depth) => {
        if (visited.has(p.key)) return;
        visited.add(p.key);
        const c = kids.get(p.key) || [];
        out.push({ p, prefix: depth ? pre + (last ? "└─ " : "├─ ") : "", childCount: c.length });
        c.forEach((x, i) => walk(x, depth ? pre + (last ? "   " : "│  ") : "", i === c.length - 1, depth + 1));
      };

      (kids.get(null) || []).forEach((p, i, a) => walk(p, "", i === a.length - 1, 0));
      items.forEach(p => { if (!visited.has(p.key)) walk(p, "", true, 0); });
      return out;
    }
    async function load() {
      if (!st.alive) return;
      try {
        const r = await api(`/processes?limit=1000&sort=${st.sort}&order=${st.order}&q=${encodeURIComponent(st.q)}`);
        const s = G.state.summary?.latest || {}; clear(bars).append("cpu ", bar(s.cpu, 12), "  mem ", bar(s.mem, 12), `  ${r.total} tasks`);
        const rows = order(r.items), keep = tbl.scrollTop; st.rows = rows;
        clear(tbl).append(table([
          { label: "PID", cls: "r", w: "70px", render: r => r.p.pid }, { label: "PPID", cls: "r dim", w: "70px", render: r => r.p.ppid },
          { label: "CPU%", cls: "r", render: r => (r.p.cpu || 0).toFixed(1) }, { label: "MEM", cls: "r", render: r => fmt.bytes(r.p.rss) },
          { label: "SIGNER", render: r => el("span", { class: r.p.signer === "unsigned" ? "st-degraded" : "dim" }, r.p.signer || "?") },
          { label: "INC", render: r => r.p.incident ? sevChip(r.p.incident) : "" },
          { label: "COMMAND", render: r => el("span", {}, el("span", { class: "dim" }, r.prefix), r.p.name, r.childCount ? el("span", { class: "chip sev-info", style: "margin-left:5px;font-size:10px;padding:0 3px" }, `(${r.childCount})`) : null, r.p.simulated ? el("span", { class: "tag-sim" }, "SIM") : null) },
          { label: "PATH", render: r => el("span", { class: "dim" }, fmt.short(r.p.exe, 70)) },
        ],
          rows, { onRow: r => select(r.p.key), selected: r => r.p.key === st.sel, rowCls: r => r.p.simulated ? "simrow" : "" }));
        tbl.scrollTop = keep;
      } catch (e) { }
    }
    async function select(key) {
      st.sel = key; detail.style.display = "block"; load();
      try {
        const d = await api("/processes/" + encodeURIComponent(key)), p = d.process;
        clear(detail).append(
          el("div", { class: "grid2" },
            kv([["name", p.name], ["pid / ppid", `${p.pid} / ${p.ppid}`], ["parent", p.parent_name], ["path", p.exe], ["sha256", p.sha256 ? fmt.short(p.sha256, 40) : "(computing…)"], ["signer", p.signer],
              ["started", fmt.datetime(p.start_ts)], ["cmdline (redacted)", fmt.short(p.cmdline, 120)]]),
            el("div", {}, el("h3", {}, "Evidence"),
              d.detections.length ? d.detections.map(x => el("div", {}, el("span", { class: "chip sev-info" }, x.evidence_class), " ", x.title)) : el("div", { class: "dim" }, "no detections"),
              d.pe ? el("div", { class: "note info" }, `PE score ${d.pe.score} (threshold ${d.pe.threshold}, model ${d.pe.model_version}, ${d.pe.inference_time_ms} ms)`) : null,
              d.children && d.children.length ? el("div", { style: "margin-top:6px" },
                el("div", { style: "font-weight:600;color:var(--accent);margin-bottom:3px" }, `Child Processes (${d.children.length}):`),
                el("div", { style: "display:flex;flex-wrap:wrap;gap:6px" },
                  d.children.map(c => el("button", { style: "font-size:11px;padding:2px 6px", onclick: () => select(c.key) }, `[PID ${c.pid}] ${c.name}`))
                )
              ) : el("div", { class: "dim", style: "margin-top:4px" }, "children: none"))),
          el("div", { style: "margin-top:8px;display:flex;gap:8px;flex-wrap:wrap" },
            p.sha256 ? el("button", { onclick: () => allow("sha256", p.sha256) }, "allowlist hash") : null, p.exe ? el("button", { onclick: () => allow("path", p.exe) }, "allowlist path") : null,
            el("button", { onclick: () => respond("terminate", st.sel, p.name) }, "terminate…"), el("button", { onclick: () => respond("suspend", st.sel, p.name) }, "suspend"), el("button", { onclick: () => respond("resume", st.sel, p.name) }, "resume"), el("button", { onclick: () => respond("quarantine", st.sel, p.name) }, "quarantine…"),
            el("button", { onclick: () => scanFile(p.exe) }, "scan file")));
      } catch (e) { clear(detail).append(el("div", { class: "dim" }, e.message)); }
    }
    async function allow(kind, value) { const reason = prompt("Reason for allowlisting (audited):"); if (!reason) return; await api("/allowlist", { method: "POST", body: { kind, value, reason } }); toast("added to allowlist"); }
    async function preview(action) { const r = await api("/actions/preview", { method: "POST", body: { action, target: st.sel } }); detail.append(el("div", { class: "note" }, `PREVIEW ONLY — nothing executed. ${action} → ${r.target.name || r.target.raw} (pid ${r.target.pid ?? "?"}). ${r.impact} ${r.reason}`)); }
    async function scanFile(p) { if (!p) return; const r = await api("/scan", { method: "POST", body: { path: p } }); detail.append(el("div", { class: "note info" }, `scan: sha256 ${r.file.sha256 || "?"} · PE=${r.file.is_pe} · signer: ${r.file.signer || "?"}${r.file.origin ? " · origin: " + (r.file.origin.zone || "?") + (r.file.origin.origin_host ? " (" + r.file.origin.origin_host + ")" : "") : ""} · model: ${r.model_status}${r.model ? " " + r.model.score + " (thr " + r.model.threshold + ")" : ""} · executed: never`)); }
    load(); const t = setInterval(load, 2500);
    return { destroy() { st.alive = false; clearInterval(t); }, onFocus() { } };
  },
};

G.apps.network = {
  name: "Network Center", short: "net", icon: "net", w: 980, h: 540, flush: true, title: h => `Guardian OS — Network Center (${h})`,
  mount(body) {
    const st = { q: "", tab: "live", alive: true, rows: [] };
    const tbl = el("div", { style: "flex:1;overflow:auto" });
    const search = el("input", { placeholder: "filter addr / port / process", style: "width:260px", oninput: e => { st.q = e.target.value; load(); } });
    const tabs = el("select", { onchange: e => { st.tab = e.target.value; load(); } }, el("option", { value: "live" }, "live connections"), el("option", { value: "history" }, "connection history (db)"));
    body.append(el("div", { class: "menubar" }, search, tabs, el("span", { class: "sp" }), el("button", { onclick: () => download("connections.json", st.rows) }, "export view")), tbl);
    async function load() {
      if (!st.alive) return;
      try {
        if (st.tab === "live") {
          const r = await api("/network/connections?q=" + encodeURIComponent(st.q)); st.rows = r.items;
          clear(tbl).append(table([{ k: "proto", label: "Netid" }, { k: "status", label: "State" }, { k: "laddr", label: "Local Address:Port" }, { k: "raddr", label: "Peer Address:Port" }, { k: "pid", label: "PID", cls: "r" }, { k: "process", label: "Process" }], r.items));
        } else {
          const r = await api("/network/flows?limit=500"); st.rows = r.items.filter(f => !st.q || JSON.stringify(f).includes(st.q));
          clear(tbl).append(table([{ label: "Time", render: f => fmt.time(f.start_ts) }, { k: "protocol", label: "Proto" }, { label: "Local", render: f => `${f.laddr}:${f.lport}` }, { label: "Remote", render: f => `${f.raddr}:${f.rport}` }, { k: "status", label: "State" }, { k: "pid", label: "PID", cls: "r" }, { label: "End", render: f => f.end_ts ? fmt.time(f.end_ts) : el("span", { class: "st-ok" }, "open") }], st.rows));
        }
      } catch (e) { }
    }
    load(); const t = setInterval(load, 3000); return { destroy() { st.alive = false; clearInterval(t); } };
  },
};
