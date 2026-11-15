"use strict";
const LOGO = String.raw`      .-""""-.
     / .--.   \
    | |    |   |    ┌─────────────┐
    | | \/ |   |    │  G U A R D  │
     \ '--'   /     │  I A N      │
      '-.__.-'      └─────────────┘
        /__\
`;

const statusCls = s => ({ available: "st-ok", ok: "st-ok", degraded: "st-degraded", unavailable: "st-unavailable", paused: "st-degraded", "read-only": "st-bad" }[s] || "");
const statusMark = s => ({ available: "[ OK ]", ok: "[ OK ]", degraded: "[WARN]", unavailable: "[ -- ]", paused: "[PAUS]", "read-only": "[FAIL]" }[s] || "[ ?? ]");

G.apps.home = {
  name: "Guardian Home", short: "home", icon: "home", w: 860, h: 560,
  title: h => `guardian@${h}: ~`,
  mount(body) {
    let alive = true;
    async function draw() {
      if (!alive) return;
      try {
        const [h, s, a] = await Promise.all([api("/health"), api("/system/summary"), api("/alerts?limit=5")]);
        G.state.health = h; G.state.summary = s; const m = s.latest || {};
        const hdr = el("div", { class: "grid2" },
          el("pre", { class: "logo", style: "margin:0" }, LOGO),
          kv([["host", `${h.hostname}`], ["os", `${h.os} ${h.architecture}`], ["build", h.os_build], ["privilege", h.admin ? "administrator" : "standard user"],
              ["agent", el("span", { class: statusCls(h.status) }, h.status.toUpperCase())], ["uptime", fmt.dur(h.uptime_s)], ["policy", "v" + h.policy_version],
              ["pe model", h.model.loaded ? `${h.model.version} (${h.model.validated ? "validated" : "NOT validated"})` : "none — rules-only"]]));
        const res = el("div", { class: "card" }, el("h4", {}, "System"),
          el("div", {}, "cpu  ", bar(m.cpu, 12)), el("div", {}, "mem  ", bar(m.mem, 12), el("span", { class: "dim" }, `  ${fmt.bytes(m.mem_used)} / ${fmt.bytes(m.mem_total)}`)),
          el("div", {}, "disk ", bar(m.disk, 12), el("span", { class: "dim" }, `  free ${fmt.bytes(m.disk_free)}`)),
          m.battery ? el("div", {}, "batt ", bar(m.battery.percent), m.battery.plugged ? " ⚡" : "") : null,
          el("div", { class: "dim" }, `${s.process_count} processes · ${s.connection_count} connections`));
        const q = h.queue;
        const qStateCls = q.state === "ok" ? "st-ok" : q.state === "warning" ? "st-degraded" : "st-bad";
        const pipe = el("div", { class: "card" }, el("h4", {}, "Pipeline & Bounded Queue"),
          el("div", {}, "queue ", bar(q.fill_pct, 12), el("span", { class: "dim" }, ` ${q.depth} / 10000 events (${q.fill_pct}%)`)),
          el("div", {}, "state ", el("span", { class: qStateCls }, `[${q.state.toUpperCase()}]`), el("span", { class: "dim" }, ` · ${fmt.bytes(q.bytes || 0)}`)),
          el("div", {}, `generated ${q.generated} · dropped `, el("span", { class: q.dropped ? "st-degraded" : "st-ok" }, `${q.dropped} (${q.drop_rate_pct}%)`)),
          el("div", { class: "dim" }, `db ${fmt.bytes(h.db.size_bytes)} · audit chain ${h.db.audit_chain_ok ? "verified" : "BROKEN"}`),
          el("div", { style: "margin-top:6px" }, el("button", { onclick: async () => { await api("/collection", { method: "POST", body: { paused: !h.paused } }); toast(h.paused ? "collection resumed" : "collection paused"); draw(); } }, h.paused ? "▶ resume collection" : "⏸ pause collection")));
        const src = el("div", { class: "card" }, el("h4", {}, "Sensors"),
          Object.entries(h.sources).filter(([k, v]) => k !== "pe_model" || v.status === "available").map(([k, v]) => el("div", { title: v.reason || "" }, el("span", { class: statusCls(v.status) }, statusMark(v.status)), " ", k)));
        const threadCols = [
          { k: "name", label: "THREAD" },
          { k: "role", label: "OS ROLE" },
          { label: "STATE", render: r => el("span", { class: statusCls(r.status) }, statusMark(r.status)) },
          { label: "SCHEDULE / SYNC PRIMITIVE", render: r => r.sync_primitive || (r.interval_s ? `every ${r.interval_s}s` : "queue.Queue") },
          { label: "HEARTBEAT AGE", cls: "r", render: r => r.last_beat_age_s !== null && r.last_beat_age_s !== undefined ? `${r.last_beat_age_s}s` : "—" },
          { label: "ERRORS", cls: "r", render: r => el("span", { class: r.errors ? "st-bad" : "dim" }, r.errors || 0) },
        ];
        const threadsCard = el("div", { class: "card", style: "margin-top:12px" },
          el("h4", {}, "Active OS Agent Threads & Synchronization"),
          table(threadCols, Array.isArray(h.threads) ? h.threads : []));
        const alerts = el("div", { class: "card" }, el("h4", {}, "Recent alerts"),
          a.items.length ? a.items.map(i => el("div", { style: "cursor:pointer", onclick: () => { WM.open("security"); setTimeout(() => emit("select-incident", i.incident_id), 50); } },
            sevChip(i.severity), " ", fmt.short(i.title, 52), i.simulated ? el("span", { class: "tag-sim" }, "SIM") : null, el("span", { class: "dim" }, "  " + fmt.ago(i.opened_at))))
            : el("div", { class: "st-ok" }, "✔ no incidents. Quiet is the goal."));
        const mods = el("div", { class: "card" }, el("h4", {}, "Open"), Object.entries(G.apps).filter(([k]) => k !== "home").map(([k, a]) => el("button", { style: "margin:2px 4px 2px 0", onclick: () => WM.open(k) }, a.short)));
        const notes = [];
        if (h.db.recovery_notice) notes.push(el("div", { class: "note" }, "⚠ " + h.db.recovery_notice));
        if (h.unavailable.includes("sysmon")) notes.push(el("div", { class: "note" }, "Sysmon is not installed (optional). Process, network, Event Log and registry monitoring still run; file-create, DNS and registry-attribution evidence is limited. See deployment/sysmon-config/."));
        clear(body).append(el("div", { class: "pad" }, hdr, el("hr", { class: "hr" }), el("div", { class: "grid3" }, res, pipe, src), threadsCard, el("div", { class: "grid2", style: "margin-top:12px" }, alerts, mods), notes));
      } catch (e) { if (alive) clear(body).append(el("div", { class: "pad st-bad" }, "agent unreachable: " + e.message)); }
    }
    draw(); const t = setInterval(draw, 3000); const off = on("health", draw);
    return { destroy() { alive = false; clearInterval(t); off(); } };
  },
};

G.apps.system = {
  name: "System Monitor", short: "sysmon", icon: "sys", w: 820, h: 560, title: h => `guardian@${h}: ~/sysmon (btop)`,
  mount(body) {
    let alive = true;
    async function draw() {
      if (!alive) return;
      try {
        const [hist, su, svc] = await Promise.all([api("/system/history"), api("/system/startup"), api("/system/services")]);
        const S = hist.samples; const last = S[S.length - 1] || {};
        const rate = key => S.map((s, i) => i ? Math.max(0, (s[key] - S[i - 1][key]) / Math.max(.1, s.ts - S[i - 1].ts)) : 0);
        const rx = rate("net_recv"), tx = rate("net_sent"), mx = Math.max(1024, ...rx, ...tx);
        const top = (await api("/processes?limit=8&sort=rss")).items;
        clear(body).append(el("div", { class: "pad" },
          el("div", { class: "grid2" },
            el("div", { class: "card" }, el("h4", {}, `CPU  ${fmt.pct(last.cpu)}  (${last.cpu_count || "?"} cores)`), spark(S.map(s => s.cpu), 360)),
            el("div", { class: "card" }, el("h4", {}, `Memory  ${fmt.pct(last.mem)}  ${fmt.bytes(last.mem_used)}`), spark(S.map(s => s.mem), 360))),
          el("div", { class: "grid2", style: "margin-top:12px" },
            el("div", { class: "card" }, el("h4", {}, `Network  ↓${fmt.bytes(rx[rx.length - 1])}/s  ↑${fmt.bytes(tx[tx.length - 1])}/s`), spark(rx, 360, 38, mx)),
            el("div", { class: "card" }, el("h4", {}, "Disk / uptime"), el("div", {}, "disk ", bar(last.disk)), el("div", { class: "dim" }, `uptime ${fmt.dur(last.uptime || 0)} · free ${fmt.bytes(last.disk_free)}`))),
          el("h3", { style: "margin-top:14px" }, "Resource-heavy processes"),
          table([{ k: "pid", label: "PID", cls: "r" }, { k: "name", label: "NAME" }, { label: "MEM", cls: "r", render: r => fmt.bytes(r.rss) }, { label: "CPU%", cls: "r", render: r => (r.cpu || 0).toFixed(1) }], top, {}),
          el("h3", { style: "margin-top:14px" }, `Startup items ${su.available ? "" : "(Windows only)"}`),
          su.items.length ? table([{ k: "location", label: "LOCATION" }, { label: "COMMAND", render: r => fmt.short(r.command, 90) }], su.items) : el("div", { class: "dim" }, "none recorded"),
          el("h3", { style: "margin-top:14px" }, `Services ${svc.available ? "" : "(Windows only)"}`),
          svc.items.length ? table([{ k: "name", label: "SERVICE" }, { label: "STATE", render: r => el("span", { class: r.status === "running" ? "st-ok" : "dim" }, r.status) }, { k: "start", label: "START" }, { label: "DISPLAY", render: r => fmt.short(r.display, 50) }], svc.items.slice(0, 150)) : el("div", { class: "dim" }, "not available on this platform")));
      } catch (e) { }
    }
    draw(); const t = setInterval(draw, 4000);
    return { destroy() { alive = false; clearInterval(t); } };
  },
};
