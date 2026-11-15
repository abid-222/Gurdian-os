"use strict";
G.apps.security = {
  name: "Security Center", short: "sec", icon: "sec", w: 1060, h: 640, flush: true, title: h => `Guardian OS — Security Center (${h})`,
  mount(body) {
    const st = { sel: null, items: [], filter: "open", alive: true };
    const list = el("div"), det = el("div", { class: "pad" }, el("div", { class: "dim" }, "Select an incident to see its evidence chain."));
    const filt = el("select", { "aria-label": "status filter", onchange: e => { st.filter = e.target.value; load(); } }, ["open", "acknowledged", "dismissed", "all"].map(x => el("option", { value: x }, x)));
    body.append(el("div", { class: "menubar" }, el("label", {}, "status ", filt), el("span", { class: "sp" }),
      el("span", { class: "dim", style: "font-size:12px" }, "Live test: python testbed/run_real_scenarios.py")),
      el("div", { class: "split", style: "flex:1;min-height:0" }, el("div", {}, list), det));

    async function load() {
      if (!st.alive) return;
      try {
        const r = await api("/alerts" + (st.filter === "all" ? "" : "?status=" + st.filter)); st.items = r.items;
        clear(list);
        if (!r.items.length) list.append(el("div", { class: "pad st-ok" }, "✔ No incidents here. Informational findings stay as quiet timeline entries."));
        r.items.forEach(i => list.append(el("div", { class: "inc" + (i.incident_id === st.sel ? " sel" : "") + (i.status !== "open" ? " done" : ""), tabindex: "0", onclick: () => select(i.incident_id), onkeydown: e => e.key === "Enter" && select(i.incident_id) },
          el("div", { class: "t" }, sevChip(i.severity), " ", fmt.short(i.title, 48), i.simulated ? el("span", { class: "tag-sim" }, "SIM") : null),
          el("div", { class: "dim" }, `${i.incident_id} · ${i.status} · ${fmt.ago(i.opened_at)} · ${(i.classes || []).join(" ")}`))));
        const b = $("#dock [data-app=security] .badge"); if (b) { b.textContent = r.items.filter(i => i.status === "open").length || ""; }
      } catch (e) { }
    }
    async function select(id) {
      st.sel = id; load();
      try {
        const d = await api("/alerts/" + id), i = d.incident; const e1 = d.detections.find(x => x.evidence_class === "E1" && x.score != null); const notes = (await api(`/alerts/${id}/notes`)).items;
        const dt = el("div", {},
          el("h3", {}, sevChip(i.severity), " ", i.title, i.simulated ? el("span", { class: "tag-sim" }, "SIM") : null),
          kv([["incident", i.incident_id], ["status", i.status], ["affected process", i.process_name ? `${i.process_name} (pid ${i.pid ?? "?"})` : "—"], ["sha256", i.sha256 ? fmt.short(i.sha256, 40) : "—"],
            ["opened", fmt.datetime(i.opened_at)], ["evidence score", `${i.risk}/100  (policy-derived, not a probability)`], ["confidence", e1 ? `PE model ${e1.model_version}: calibrated score ${(+e1.score).toFixed(2)} vs threshold ${e1.threshold} (one evidence class, not a verdict)` : "n/a — no calibrated model score in this incident"], ["policy", `v${i.policy_version}  join ${d.policy.join_window_s}s · merge ${d.policy.merge_window_s}s`],
            ["model", d.model.loaded ? `${d.model.info.version}` : "none installed (rules-only)"]]),
          el("div", { class: "note" }, el("b", {}, "Caveat: "), i.caveat),
          el("h3", { style: "margin-top:12px" }, "Evidence timeline"),
          table([{ label: "CLASS", render: x => el("span", { class: "chip sev-info", title: x.class_name }, x.evidence_class) }, { label: "STRENGTH", render: x => x.strength }, { label: "RULE", render: x => x.rule_id }, { label: "FINDING", render: x => x.title }, { label: "WHY", render: x => fmt.short(x.reason, 90) }], d.detections),
          el("h3", { style: "margin-top:12px" }, "Recommended investigation steps"),
          el("ol", { style: "margin:0;padding-left:20px" }, (i.steps || []).map(s => el("li", {}, s))),
          el("div", { style: "margin-top:12px;display:flex;gap:8px;flex-wrap:wrap" },
            el("button", { class: "primary", disabled: i.status !== "open", onclick: async () => { await api(`/alerts/${id}/acknowledge`, { method: "POST" }); toast("acknowledged"); select(id); } }, "acknowledge"),
            el("button", { disabled: i.status === "dismissed", onclick: async () => { const reason = prompt("Reason for dismissing (recorded in the audit log):"); if (!reason || reason.length < 3) return; await api(`/alerts/${id}/dismiss`, { method: "POST", body: { reason } }); select(id); } }, "dismiss…"),
            el("button", { onclick: async () => { const r = await fetch(`/api/v1/alerts/${id}/export`, { headers: { "X-Guardian-Token": G.token } }); if (r.ok) download(`${id}.json`, await r.json()); else toast("export failed", "high"); } }, "export investigation"),
            i.process_key && i.process_name ? el("button", { onclick: () => respond("terminate", i.process_key, i.process_name, () => select(id)) }, "terminate process…") : null, i.process_key && i.process_name ? el("button", { onclick: () => respond("quarantine", i.process_key, i.process_name, () => select(id)) }, "quarantine file…") : null),
          el("h3", { style: "margin-top:12px" }, "Investigation notes"),
          notes.length ? notes.map(n => el("div", { class: "dim" }, `${fmt.datetime(n.ts)}  ${n.body}`)) : el("div", { class: "dim" }, "no notes yet"),
          (() => { const inp = el("input", { placeholder: "add a note (kept locally, included in the export)", style: "width:70%", "aria-label": "investigation note" });
            const add = async () => { const v = inp.value.trim(); if (!v) return; await api(`/alerts/${id}/notes`, { method: "POST", body: { body: v } }); select(id); };
            inp.addEventListener("keydown", e => { if (e.key === "Enter") add(); });
            return el("div", { style: "margin-top:6px;display:flex;gap:6px" }, inp, el("button", { onclick: add }, "add note")); })(),
          d.audit.length ? el("div", {}, el("h3", { style: "margin-top:12px" }, "User decisions (audit)"), d.audit.map(a => el("div", { class: "dim" }, `${fmt.datetime(a.ts)}  ${a.actor}  ${a.action}  ${a.detail || ""}`))) : null);
        clear(det).append(dt);
      } catch (e) { clear(det).append(el("div", { class: "pad st-bad" }, e.message)); }
    }
    load(); const t = setInterval(load, 4000); const off = on("incident", load); const off2 = on("select-incident", select);
    return { destroy() { st.alive = false; clearInterval(t); off(); off2(); } };
  },
};

G.apps.timeline = {
  name: "Event Timeline", short: "log", icon: "log", w: 1000, h: 560, flush: true, title: h => `Guardian OS — Event Timeline (${h})`,
  mount(body) {
    const st = { follow: true, alive: true, f: { type: "", source: "", q: "", pid: "" }, rows: [] };
    const view = el("div", { class: "pad", style: "flex:1;overflow:auto;padding-top:4px" });
    const inp = (k, ph, w) => el("input", { placeholder: ph, style: `width:${w}px`, oninput: e => { st.f[k] = e.target.value.trim(); load(); }, "aria-label": ph });
    const typeSel = el("select", { "aria-label": "event type", onchange: e => { st.f.type = e.target.value; load(); } }, ["", "process_start", "process_end", "network_connect", "persistence_change", "sensor_tamper", "defender_detection", "windows_event", "dns_query", "file_create", "coverage_gap"].map(x => el("option", { value: x }, x || "all types")));
    const follow = el("label", {}, el("input", { type: "checkbox", checked: true, onchange: e => { st.follow = e.target.checked; } }), " follow");
    body.append(el("div", { class: "menubar" }, typeSel, inp("source", "source", 100), inp("pid", "pid", 70), inp("q", "search text / hash", 200), el("span", { class: "sp" }), follow, el("button", { onclick: () => download("timeline.json", st.rows) }, "export")), view);
    async function load() {
      if (!st.alive) return;
      const p = new URLSearchParams({ limit: 400 }); for (const [k, v] of Object.entries(st.f)) if (v) p.set(k, v);
      try {
        const r = await api("/events?" + p); st.rows = r.items; const rows = [...r.items].reverse();
        clear(view);
        rows.forEach(e => { const a = e.attributes || {}; const what = a.name || a.remote || a.target || a.kind || a.query || (e.image_path || "").split(/[\\/]/).pop() || "";
          view.append(el("div", { class: "logline t-" + e.event_type, title: JSON.stringify(a) }, el("span", { class: "t" }, fmt.time(e.ts) + " "), el("span", { class: "src" }, e.source.padEnd(13)), el("span", { class: "ty" }, e.event_type.padEnd(19)), e.pid ? `[${e.pid}] ` : "", what,
            e.source === "simulation" ? el("span", { class: "tag-sim" }, "SIM") : null, e.privacy_flags.length ? el("span", { class: "dim" }, "  ⌀" + e.privacy_flags.length) : null)); });
        if (!rows.length) view.append(el("div", { class: "dim" }, "-- No entries --"));
        if (st.follow) view.scrollTop = view.scrollHeight;
      } catch (e) { }
    }
    load(); const t = setInterval(load, 3000); return { destroy() { st.alive = false; clearInterval(t); } };
  },
};
