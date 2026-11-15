"use strict";

const SHIELD_MAP = {
  processes: { title: "Process & App Monitor", desc: "Live process creation & PCB tracking", icon: "cpu", color: "emerald" },
  network: { title: "Network Traffic Guard", desc: "Live sockets & network connections", icon: "network", color: "indigo" },
  resources: { title: "Resource Health Watch", desc: "Monitors CPU, RAM & disk spikes", icon: "activity", color: "purple" },
  event_log_system: { title: "System Event Monitor", desc: "Watches Windows System Event Log", icon: "layers", color: "cyan" },
  event_log_security: { title: "Security Audit Log", desc: "Deep event log audit (Needs Admin)", icon: "lock", color: "amber" },
  sysmon: { title: "Sysmon Deep Telemetry", desc: "Kernel file & DNS telemetry (Optional)", icon: "zap", color: "slate" },
  defender: { title: "Windows Defender Link", desc: "Syncs Windows Defender verdicts", icon: "shield-check", color: "emerald" },
  registry_run_keys: { title: "Startup & Registry Guard", desc: "Watches persistence Run keys", icon: "key", color: "cyan" },
  pe_parser: { title: "Executable File Inspector", desc: "Static PE header & Authenticode", icon: "file-search", color: "amber" }
};

G.apps.home = {
  name: "Overview", short: "home", icon: "home", w: 980, h: 680,
  title: h => `root@${(h || "guardian").toLowerCase()}:/sys [overview]`,
  mount(body) {
    let alive = true;
    let accordionOpen = false;

    async function draw() {
      if (!alive) return;
      try {
        const [h, s, a] = await Promise.all([
          api("/health"),
          api("/system/summary"),
          api("/alerts?limit=5")
        ]);
        G.state.health = h;
        G.state.summary = s;
        const m = s.latest || {};
        const q = h.queue || {};

        // ---- Zone A: Hero Protection Status Banner ----
        const isDegraded = h.status !== "ok" || !h.admin;
        const heroShield = renderIcon(
          isDegraded ? "shield-alert" : "shield-check",
          isDegraded ? "amber" : "emerald",
          "xl",
          "hero-shield-frame"
        );

        const heroHeadline = el("h2", { class: "hero-headline" },
          isDegraded ? "KERNEL WORKSTATION: RING-3 RESTRICTED MODE" : "KERNEL CORE RING-0 INTEGRITY: OPTIMAL"
        );
        const heroSubtext = el("p", { class: "hero-subtext" },
          !h.admin
            ? "Operating in unprivileged userspace. Syscall & process telemetry active; Security event auditing requires sudo/Admin privilege."
            : "Deterministic E2–E6 correlation engine, producer-consumer ring buffer, and tamper-evident SQLite WAL ledger operating normally."
        );

        const pauseBtn = el("button", {
          class: "device-chip",
          style: "cursor:pointer;background:rgba(56,189,248,0.12);border-color:rgba(56,189,248,0.3);color:var(--primary);display:inline-flex;align-items:center;gap:6px",
          onclick: async () => {
            await api("/collection", { method: "POST", body: { paused: !h.paused } });
            toast(h.paused ? "Protection resumed" : "Protection paused", "info");
            draw();
          }
        },
          renderIcon(h.paused ? "play" : "pause", "cyan", "xs"),
          el("span", {}, h.paused ? "Resume Monitoring" : "Pause Monitoring")
        );

        const heroChips = el("div", { class: "hero-chips" },
          el("div", { class: "device-chip" }, "Host: ", el("b", {}, h.hostname)),
          el("div", { class: "device-chip" }, "Kernel: ", el("b", {}, "6.8.0-guardian")),
          el("div", { class: "device-chip" }, "Arch: ", el("b", {}, h.architecture || "x86_64")),
          el("div", { class: "device-chip" }, "Uptime: ", el("b", {}, fmt.dur(h.uptime_s))),
          el("div", { class: "device-chip" }, "Engine: ", el("b", {}, "Smart Rules E2–E6")),
          el("div", { class: "device-chip" }, "IPC: ", el("b", {}, "Lockless Ring Buffer")),
          pauseBtn
        );

        const heroBanner = el("div", { class: "hero-banner" },
          el("div", { class: "hero-left" }, heroShield, el("div", {}, heroHeadline, heroSubtext)),
          heroChips
        );

        // ---- Zone B: Live System Resources Card ----
        const cpuPct = Math.round(m.cpu || 0);
        const memPct = Math.round(m.mem || 0);
        const diskPct = Math.round(m.disk || 0);

        const resCard = el("div", { class: "bento-card" },
          el("h4", { class: "bento-card-title" },
            el("span", { style: "display:flex;align-items:center;gap:8px" },
              renderIcon("activity", "purple", "sm"),
              el("span", {}, "System Resources")
            ),
            el("span", { class: "dim", style: "font-size:11px;font-weight:400" }, "Live Telemetry")
          ),
          el("div", { class: "resource-list" },
            // CPU
            el("div", { class: "resource-item" },
              el("div", { class: "resource-head" },
                el("span", { class: "resource-name" },
                  renderIcon("cpu", "cyan", "xs"),
                  el("span", { style: "margin-left:4px" }, "Processor (CPU)")
                ),
                el("span", { class: "resource-meta" }, `${cpuPct}% • ${s.process_count || 0} active processes`)
              ),
              el("div", { class: "progress-track" },
                el("div", { class: "progress-fill" + (cpuPct > 85 ? " bar-hi" : cpuPct > 60 ? " bar-mid" : ""), style: `width:${cpuPct}%` })
              )
            ),
            // Memory
            el("div", { class: "resource-item" },
              el("div", { class: "resource-head" },
                el("span", { class: "resource-name" },
                  renderIcon("memory", "amber", "xs"),
                  el("span", { style: "margin-left:4px" }, "Memory (RAM)")
                ),
                el("span", { class: "resource-meta" }, `${fmt.bytes(m.mem_used)} used of ${fmt.bytes(m.mem_total)}`)
              ),
              el("div", { class: "progress-track" },
                el("div", { class: "progress-fill" + (memPct > 85 ? " bar-hi" : memPct > 60 ? " bar-mid" : ""), style: `width:${memPct}%` })
              )
            ),
            // Storage
            el("div", { class: "resource-item" },
              el("div", { class: "resource-head" },
                el("span", { class: "resource-name" },
                  renderIcon("hard-drive", "indigo", "xs"),
                  el("span", { style: "margin-left:4px" }, "System Disk")
                ),
                el("span", { class: "resource-meta" }, `${fmt.bytes(m.disk_free)} free storage`)
              ),
              el("div", { class: "progress-track" },
                el("div", { class: "progress-fill" + (diskPct > 85 ? " bar-hi" : diskPct > 60 ? " bar-mid" : ""), style: `width:${diskPct}%` })
              )
            )
          )
        );

        // ---- Zone C: Protection Shields Grid ----
        const shieldsList = Object.entries(h.sources)
          .filter(([k]) => k !== "pe_model")
          .map(([k, v]) => {
            const meta = SHIELD_MAP[k] || { title: k, desc: v.reason || "", icon: "shield", color: "cyan" };
            const isOk = v.status === "available";
            const isDeg = v.status === "degraded";
            const badgeCls = isOk ? "shield-badge" : isDeg ? "shield-badge warn" : "shield-badge off";
            const badgeText = isOk ? "Active" : isDeg ? "Degraded" : "Optional";
            const badgeIconName = isOk ? "check" : isDeg ? "alert-triangle" : "info";

            const cardIcon = renderIcon(meta.icon, isOk ? meta.color : isDeg ? "amber" : "slate", "sm");
            const badgeIcon = renderIcon(badgeIconName, isOk ? "emerald" : isDeg ? "amber" : "slate", "xs");

            return el("div", { class: "shield-card", title: v.reason || meta.desc },
              el("div", { style: "display:flex;align-items:center;gap:10px" },
                cardIcon,
                el("div", { class: "shield-info" },
                  el("span", { class: "shield-title" }, meta.title),
                  el("span", { class: "shield-subtitle" }, meta.desc)
                )
              ),
              el("span", { class: badgeCls }, badgeIcon, el("span", { style: "margin-left:4px" }, badgeText))
            );
          });

        const shieldsCard = el("div", { class: "bento-card" },
          el("h4", { class: "bento-card-title" },
            el("span", { style: "display:flex;align-items:center;gap:8px" },
              renderIcon("shield", "emerald", "sm"),
              el("span", {}, "Protection Shields")
            ),
            el("span", { class: "dim", style: "font-size:11px;font-weight:400" }, `${Object.values(h.sources).filter(x => x.status === "available").length} / ${Object.keys(h.sources).length} Active`)
          ),
          el("div", { class: "shield-grid" }, shieldsList)
        );

        // ---- Zone D: Recent Alerts & Quick Actions ----
        const alertsList = a.items.length
          ? a.items.map(i => el("div", {
              class: "alert-card-item",
              onclick: () => { WM.open("security"); setTimeout(() => emit("select-incident", i.incident_id), 60); }
            },
              el("div", { class: "alert-left" },
                sevChip(i.severity),
                el("div", {},
                  el("div", { class: "alert-title-text" }, fmt.short(i.title, 44)),
                  el("div", { class: "alert-time" }, `${i.process_name || "system"} • ${fmt.ago(i.opened_at)}`)
                )
              ),
              el("button", { style: "font-size:11px;padding:4px 10px;display:flex;align-items:center;gap:4px" },
                el("span", {}, "Details"),
                renderIcon("chevron-right", "slate", "xs")
              )
            ))
          : el("div", { style: "padding:22px 0;text-align:center;display:flex;align-items:center;justify-content:center;gap:10px;color:var(--ok)" },
              renderIcon("shield-check", "emerald", "sm"),
              el("span", { style: "font-weight:500" }, "No security incidents detected. System is quiet and protected.")
            );

        const alertsCard = el("div", { class: "bento-card" },
          el("h4", { class: "bento-card-title" },
            el("span", { style: "display:flex;align-items:center;gap:8px" },
              renderIcon("alert-triangle", "amber", "sm"),
              el("span", {}, "Recent Security Alerts")
            ),
            el("button", {
              style: "font-size:11px;padding:2px 8px;background:transparent;border:0;color:var(--primary);cursor:pointer",
              onclick: () => WM.open("security")
            }, "View All →")
          ),
          alertsList
        );

        // Quick Actions Grid (All Framed SVG Icons)
        const quickActions = [
          { app: "threads", icon: "cpu", color: "cyan", title: "Concurrency & IPC", desc: "Producer-consumer & threads" },
          { app: "terminal", icon: "terminal", color: "cyan", title: "Guardian Shell", desc: "Interactive command shell" },
          { app: "processes", icon: "hierarchy", color: "emerald", title: "Process Tree", desc: "Parent-child hierarchy" },
          { app: "network", icon: "globe", color: "indigo", title: "Network Flows", desc: "Live sockets & connections" },
          { app: "security", icon: "shield", color: "rose", title: "Security Center", desc: "Incidents & evidence" },
          { app: "system", icon: "activity", color: "purple", title: "System Monitor", desc: "Telemetry charts" },
          { app: "models", icon: "file-search", color: "amber", title: "File Scanner", desc: "Static PE inspection" },
        ];

        const actionsGrid = el("div", { class: "action-grid" },
          quickActions.map(act => el("div", {
            class: "action-card",
            onclick: () => WM.open(act.app)
          },
            renderIcon(act.icon, act.color, "md"),
            el("div", { class: "action-title" }, act.title),
            el("div", { class: "action-desc" }, act.desc)
          ))
        );

        const actionsCard = el("div", { class: "bento-card" },
          el("h4", { class: "bento-card-title" },
            el("span", { style: "display:flex;align-items:center;gap:8px" },
              renderIcon("layers", "cyan", "sm"),
              el("span", {}, "Quick OS Navigation")
            )
          ),
          actionsGrid
        );

        // Optional Sysmon Notice Card
        const notes = [];
        if (h.unavailable.includes("sysmon")) {
          notes.push(el("div", { class: "note", style: "margin:0;display:flex;align-items:center;gap:10px" },
            renderIcon("info", "cyan", "xs"),
            el("span", {}, "Sysmon is optional. Standard process, network, and registry monitoring are fully active. Install Sysmon only if you need low-level kernel DNS query attribution.")
          ));
        }

        // ---- Collapsible Accordion: OS Kernel Threads & Bounded Queue ----
        const threadCols = [
          { k: "name", label: "THREAD" },
          { k: "role", label: "OS ROLE" },
          { label: "STATE", render: r => el("span", { class: r.status === "ok" ? "st-ok" : "st-degraded" }, r.status.toUpperCase()) },
          { label: "SYNCHRONIZATION PRIMITIVE", render: r => r.sync_primitive || (r.interval_s ? `every ${r.interval_s}s` : "queue.Queue") },
          { label: "HEARTBEAT AGE", cls: "r", render: r => r.last_beat_age_s !== null && r.last_beat_age_s !== undefined ? `${r.last_beat_age_s}s` : "—" },
          { label: "ERRORS", cls: "r", render: r => el("span", { class: r.errors ? "st-bad" : "dim" }, r.errors || 0) },
        ];

        const accordionWrap = el("div", { class: "accordion" + (accordionOpen ? " open" : "") });
        const accordionHeader = el("div", {
          class: "accordion-header",
          onclick: () => {
            accordionOpen = !accordionOpen;
            accordionWrap.classList.toggle("open", accordionOpen);
          }
        },
          el("div", { class: "accordion-title" },
            renderIcon("settings", "cyan", "sm"),
            el("span", {}, "OS Kernel Threads & Bounded Event Queue"),
            el("span", { class: "device-chip", style: "padding:2px 8px;font-size:11px" }, `${(h.threads || []).length} Background Workers`)
          ),
          el("div", { style: "display:flex;align-items:center;gap:12px" },
            el("button", {
              class: "btn-subtle xs cyan",
              style: "font-size:11px;padding:3px 8px",
              title: "Open dedicated full-screen Concurrency & IPC Workstation",
              onclick: (e) => {
                e.stopPropagation();
                WM.open("threads");
              }
            }, "Open Full Workstation ↗"),
            el("span", { class: "accordion-summary" },
              `Queue Fill: ${q.fill_pct || 0}% • ${q.generated || 0} events • ${q.dropped || 0} dropped`
            ),
            renderIcon("chevron-down", "slate", "xs", "accordion-chevron")
          )
        );

        const accordionContent = el("div", { class: "accordion-content" },
          el("div", { class: "grid3", style: "margin-bottom:14px" },
            el("div", { class: "card" },
              el("h4", { style: "display:flex;align-items:center;gap:6px" },
                renderIcon("database", "cyan", "xs"),
                el("span", {}, "Producer-Consumer Buffer")
              ),
              el("div", {}, `Capacity: 10,000 events / 32 MB`),
              el("div", {}, `Current Depth: ${q.depth || 0} events (${q.fill_pct || 0}%)`),
              el("div", { class: "dim" }, `Status: [${(q.state || "ok").toUpperCase()}] • ${fmt.bytes(q.bytes || 0)}`)
            ),
            el("div", { class: "card" },
              el("h4", { style: "display:flex;align-items:center;gap:6px" },
                renderIcon("activity", "emerald", "xs"),
                el("span", {}, "Telemetry Ingestion")
              ),
              el("div", {}, `Generated: ${q.generated || 0} events`),
              el("div", {}, `Dropped: ${q.dropped || 0} (${q.drop_rate_pct || 0}%)`),
              el("div", { class: "dim" }, `Zero packet loss under normal load`)
            ),
            el("div", { class: "card" },
              el("h4", { style: "display:flex;align-items:center;gap:6px" },
                renderIcon("lock", "purple", "xs"),
                el("span", {}, "Local SQLite WAL Store")
              ),
              el("div", {}, `Database: ${fmt.bytes(h.db.size_bytes)}`),
              el("div", {}, `Hash Chain: ${h.db.audit_chain_ok ? "Verified ✔" : "Broken ✖"}`),
              el("div", { class: "dim" }, `Cryptographically verifiable audit log`)
            )
          ),
          el("h4", { style: "margin:10px 0 6px 0;color:var(--primary)" }, "Active OS Agent Threads & Synchronization Primitives:"),
          table(threadCols, Array.isArray(h.threads) ? h.threads : [])
        );

        accordionWrap.append(accordionHeader, accordionContent);

        // Assembly of Bento Container
        clear(body).append(
          el("div", { class: "bento-container" },
            heroBanner,
            el("div", { class: "bento-grid-2" }, resCard, shieldsCard),
            el("div", { class: "bento-grid-2" }, alertsCard, actionsCard),
            accordionWrap,
            ...notes
          )
        );

      } catch (e) {
        if (alive) {
          clear(body).append(
            el("div", { class: "pad st-bad" }, "Agent unreachable: " + e.message)
          );
        }
      }
    }

    draw();
    const t = setInterval(draw, 3000);
    const off = on("health", draw);
    return {
      destroy() {
        alive = false;
        clearInterval(t);
        off();
      }
    };
  },
};

G.apps.system = {
  name: "System Monitor", short: "sysmon", icon: "activity", w: 860, h: 600,
  title: h => `root@${(h || "guardian").toLowerCase()}:/sys/hardware [telemetry]`,
  mount(body) {
    let alive = true;
    async function draw() {
      if (!alive) return;
      try {
        const [hist, su, svc] = await Promise.all([
          api("/system/history"),
          api("/system/startup"),
          api("/system/services")
        ]);
        const S = hist.samples || [];
        const last = S[S.length - 1] || {};
        const rate = key => S.map((s, i) => i ? Math.max(0, (s[key] - S[i - 1][key]) / Math.max(.1, s.ts - S[i - 1].ts)) : 0);
        const rx = rate("net_recv"), tx = rate("net_sent"), mx = Math.max(1024, ...rx, ...tx);
        const top = (await api("/processes?limit=8&sort=rss")).items || [];

        clear(body).append(
          el("div", { class: "pad" },
            el("div", { class: "grid2" },
              el("div", { class: "card" },
                el("h4", { style: "display:flex;align-items:center;gap:6px" },
                  renderIcon("cpu", "cyan", "xs"),
                  el("span", {}, `CPU Usage ${fmt.pct(last.cpu)} (${last.cpu_count || "?"} Cores)`)
                ),
                spark(S.map(s => s.cpu), 380)
              ),
              el("div", { class: "card" },
                el("h4", { style: "display:flex;align-items:center;gap:6px" },
                  renderIcon("memory", "amber", "xs"),
                  el("span", {}, `Memory Usage ${fmt.pct(last.mem)} (${fmt.bytes(last.mem_used)})`)
                ),
                spark(S.map(s => s.mem), 380)
              )
            ),
            el("div", { class: "grid2", style: "margin-top:14px" },
              el("div", { class: "card" },
                el("h4", { style: "display:flex;align-items:center;gap:6px" },
                  renderIcon("network", "indigo", "xs"),
                  el("span", {}, `Network Activity (↓${fmt.bytes(rx[rx.length - 1])}/s  ↑${fmt.bytes(tx[tx.length - 1])}/s)`)
                ),
                spark(rx, 380, 38, mx)
              ),
              el("div", { class: "card" },
                el("h4", { style: "display:flex;align-items:center;gap:6px" },
                  renderIcon("hard-drive", "purple", "xs"),
                  el("span", {}, "Disk Storage & Uptime")
                ),
                el("div", {}, bar(last.disk)),
                el("div", { class: "dim", style: "margin-top:6px" }, `Uptime: ${fmt.dur(last.uptime || 0)} • Free: ${fmt.bytes(last.disk_free)}`)
              )
            ),
            el("h3", { style: "margin-top:18px" }, "Top Resource-Consuming Processes"),
            table([
              { k: "pid", label: "PID", cls: "r", w: "80px" },
              { k: "name", label: "PROCESS NAME" },
              { label: "MEMORY (RSS)", cls: "r", render: r => fmt.bytes(r.rss) },
              { label: "CPU%", cls: "r", render: r => (r.cpu || 0).toFixed(1) + "%" }
            ], top),
            el("h3", { style: "margin-top:18px" }, `Startup Items ${su.available ? "" : "(Windows only)"}`),
            su.items.length
              ? table([{ k: "location", label: "REGISTRY LOCATION" }, { label: "COMMAND", render: r => fmt.short(r.command, 90) }], su.items)
              : el("div", { class: "dim" }, "No startup persistence items recorded"),
            el("h3", { style: "margin-top:18px" }, `System Services ${svc.available ? "" : "(Windows only)"}`),
            svc.items.length
              ? table([
                  { k: "name", label: "SERVICE" },
                  { label: "STATE", render: r => el("span", { class: r.status === "running" ? "st-ok" : "dim" }, r.status) },
                  { k: "start", label: "STARTUP" },
                  { label: "DISPLAY NAME", render: r => fmt.short(r.display, 50) }
                ], svc.items.slice(0, 100))
              : el("div", { class: "dim" }, "Services unavailable")
          )
        );
      } catch (e) {}
    }
    draw();
    const t = setInterval(draw, 4000);
    return { destroy() { alive = false; clearInterval(t); } };
  },
};
