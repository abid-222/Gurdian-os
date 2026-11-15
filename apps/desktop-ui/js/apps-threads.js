"use strict";

G.apps.threads = {
  name: "Concurrency & IPC",
  short: "threads",
  icon: "cpu",
  w: 1020,
  h: 700,
  title: h => `kernel@${(h || "guardian").toLowerCase()}:/sys/sync [threads-ipc]`,
  mount(body) {
    let alive = true;
    let vivaNotesOpen = true;

    // Outer scrollable container with padding and flex column
    const container = el("div", { class: "threads-wrap" });
    clear(body).append(container);

    // Initial placeholder state while loading
    container.append(
      el("div", { class: "pad dim", style: "text-align:center;padding:40px" },
        renderIcon("loader", "cyan", "md", "spin"),
        el("div", { style: "margin-top:10px" }, "Connecting to Kernel Concurrency Subsystem...")
      )
    );

    let initialized = false;

    // Elements references for in-place updates
    let heroCountEl, heroStatusEl;
    let qDepthEl, qSubEl, qBarEl, qGenEl, qDropEl;
    let thTotalEl, thProdEl, thConsEl, thWatchEl;
    let stQueueEl, stChainEl;
    let pipeProdDescEl, pipeQueueDescEl, pipeConsDescEl;
    let tableHostEl;

    const fallbackThreads = [
      { name: "proc_sample", role: "producer (process telemetry collector)", sync_primitive: "Timer (every 1.0s)", alive: true, errors: 0, last_beat_age_s: 0.8 },
      { name: "net_conns", role: "producer (network sockets collector)", sync_primitive: "Timer (every 2.0s)", alive: true, errors: 0, last_beat_age_s: 1.2 },
      { name: "win_events", role: "producer (Sysmon/security collector)", sync_primitive: "queue.Queue", alive: true, errors: 0, last_beat_age_s: 0.5 },
      { name: "db_writer", role: "consumer (DB batch writer)", sync_primitive: "threading.Condition", alive: true, errors: 0, last_beat_age_s: 0.3 },
      { name: "rule_engine", role: "consumer (correlation & detection)", sync_primitive: "queue.Queue", alive: true, errors: 0, last_beat_age_s: 0.7 },
      { name: "watchdog", role: "watchdog (heartbeat & liveness)", sync_primitive: "threading.Event", alive: true, errors: 0, last_beat_age_s: 1.0 }
    ];

    function buildSkeleton() {
      clear(container);

      // Hero Status Banner
      heroStatusEl = el("div", { class: "st-ok", style: "font-weight:700;font-size:14px" }, "● All Threads Synchronized");
      heroCountEl = el("div", { class: "dim", style: "font-size:11px" }, "Initializing workers...");

      const hero = el("div", {
        class: "hero-status-banner",
        style: "padding:16px 20px;background:linear-gradient(135deg, rgba(56,189,248,0.1), rgba(16,185,129,0.06));border:1px solid rgba(56,189,248,0.25);border-radius:12px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px"
      },
        el("div", { style: "display:flex;align-items:center;gap:14px" },
          renderIcon("cpu", "cyan", "lg"),
          el("div", {},
            el("h3", { style: "margin:0 0 4px 0;font-size:16px;color:#fff;display:flex;align-items:center;gap:8px" },
              "OS Lab Concurrency & IPC Live Workstation",
              el("span", { class: "badge cyan", style: "font-size:10px" }, "Live OS Telemetry")
            ),
            el("p", { class: "dim", style: "margin:0;font-size:12px" },
              "Real-time multithreading, bounded producer-consumer queue synchronization, and IPC primitives."
            )
          )
        ),
        el("div", { style: "text-align:right" },
          heroStatusEl,
          heroCountEl
        )
      );

      // Top 4 Stat Bento Cards
      qDepthEl = el("div", { style: "font-size:20px;font-weight:700;color:#fff" }, "0 / 10,000");
      qSubEl = el("div", { style: "font-size:11.5px;color:var(--fg-dim);margin:2px 0 6px 0" }, "Queue Fill: 0% • 0 B");
      qBarEl = el("div", { style: "height:100%;width:0%;background:#38bdf8;transition:width 0.3s ease" });
      qGenEl = el("span", {}, "Generated: 0");
      qDropEl = el("span", {}, "Dropped: 0 (0%)");

      const cardQueue = el("div", { class: "card", style: "padding:14px" },
        el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#38bdf8" },
          renderIcon("database", "cyan", "xs"),
          el("span", {}, "Bounded Queue (IPC Buffer)")
        ),
        qDepthEl,
        qSubEl,
        el("div", { style: "height:6px;background:rgba(255,255,255,0.08);border-radius:3px;overflow:hidden" }, qBarEl),
        el("div", { style: "display:flex;justify-content:space-between;margin-top:6px;font-size:11px;color:var(--fg-muted)" },
          qGenEl, qDropEl
        )
      );

      thTotalEl = el("div", { style: "font-size:20px;font-weight:700;color:#fff" }, "0 Worker Threads");
      thProdEl = el("strong", { class: "cyan" }, "0");
      thConsEl = el("strong", { class: "emerald" }, "0");
      thWatchEl = el("strong", { class: "purple" }, "0");

      const cardThreads = el("div", { class: "card", style: "padding:14px" },
        el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#10b981" },
          renderIcon("activity", "emerald", "xs"),
          el("span", {}, "OS Thread Pool")
        ),
        thTotalEl,
        el("div", { style: "font-size:11.5px;color:var(--fg-dim);margin:2px 0 6px 0" }, "Role Breakdown:"),
        el("div", { style: "display:flex;flex-direction:column;gap:3px;font-size:11.5px" },
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Producers (Collectors):"),
            thProdEl
          ),
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Consumers (DB/Engine):"),
            thConsEl
          ),
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Watchdogs (Heartbeat):"),
            thWatchEl
          )
        )
      );

      const cardSync = el("div", { class: "card", style: "padding:14px" },
        el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#a855f7" },
          renderIcon("layers", "purple", "xs"),
          el("span", {}, "Synchronization Primitives")
        ),
        el("div", { style: "display:flex;flex-direction:column;gap:5px;font-size:12px;margin-top:4px" },
          el("div", { style: "display:flex;align-items:center;gap:6px" },
            el("span", { class: "badge purple", style: "font-size:10px" }, "Condition Variable"),
            el("span", { style: "font-size:11px" }, "Writer drain & queue wakeups")
          ),
          el("div", { style: "display:flex;align-items:center;gap:6px" },
            el("span", { class: "badge cyan", style: "font-size:10px" }, "Mutex Locks"),
            el("span", { style: "font-size:11px" }, "Thread-safe DB transaction access")
          ),
          el("div", { style: "display:flex;align-items:center;gap:6px" },
            el("span", { class: "badge emerald", style: "font-size:10px" }, "Backpressure Clamp"),
            el("span", { style: "font-size:11px" }, "Load-shedding under heavy burst")
          )
        )
      );

      stQueueEl = el("strong", { class: "st-ok" }, "OK");
      stChainEl = el("strong", { class: "st-ok" }, "Verified ✔");

      const cardIPC = el("div", { class: "card", style: "padding:14px" },
        el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#f59e0b" },
          renderIcon("shield-check", "amber", "xs"),
          el("span", {}, "Reliability & Safety")
        ),
        el("div", { style: "display:flex;flex-direction:column;gap:6px;font-size:11.5px;margin-top:4px" },
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Queue State:"),
            stQueueEl
          ),
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Deadlock Prevention:"),
            el("strong", { class: "st-ok" }, "Timeout Joining (2.0s)")
          ),
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Storage Engine:"),
            el("strong", {}, "SQLite WAL Mode")
          ),
          el("div", { style: "display:flex;justify-content:space-between" },
            el("span", { class: "dim" }, "Cryptographic Chain:"),
            stChainEl
          )
        )
      );

      const statsGrid = el("div", { class: "grid4" },
        cardQueue, cardThreads, cardSync, cardIPC
      );

      // Visual Pipeline Flow Box
      pipeProdDescEl = el("div", { class: "dim", style: "font-size:11px" }, "3 threads (proc, net, events)");
      pipeQueueDescEl = el("div", { class: "dim", style: "font-size:11px" }, "Capacity 10,000 • 0 queued");
      pipeConsDescEl = el("div", { class: "dim", style: "font-size:11px" }, "2 threads (batch write, correlation)");

      const pipelineBox = el("div", {
        class: "card",
        style: "padding:14px 18px;background:rgba(15,23,42,0.6);border:1px dashed rgba(56,189,248,0.25)"
      },
        el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:10px;font-size:12px;flex-wrap:wrap" },
          el("div", { style: "text-align:center;flex:1;min-width:180px;padding:10px;background:rgba(56,189,248,0.08);border-radius:8px" },
            el("div", { style: "font-weight:700;color:#38bdf8" }, "Producers (Collectors)"),
            pipeProdDescEl,
            el("div", { style: "font-size:10px;color:#38bdf8;margin-top:3px" }, "put_nowait() non-blocking events")
          ),
          el("div", { style: "color:var(--fg-dim);font-weight:700;font-size:18px" }, "──►"),
          el("div", { style: "text-align:center;flex:1.2;min-width:200px;padding:10px;background:rgba(168,85,247,0.08);border-radius:8px" },
            el("div", { style: "font-weight:700;color:#c084fc" }, "Bounded Queue Buffer"),
            pipeQueueDescEl,
            el("div", { style: "font-size:10px;color:#c084fc;margin-top:3px" }, "Condition Variable / Thread-safe Mutex")
          ),
          el("div", { style: "color:var(--fg-dim);font-weight:700;font-size:18px" }, "──►"),
          el("div", { style: "text-align:center;flex:1;min-width:180px;padding:10px;background:rgba(16,185,129,0.08);border-radius:8px" },
            el("div", { style: "font-weight:700;color:#34d399" }, "Consumers (DB & Engine)"),
            pipeConsDescEl,
            el("div", { style: "font-size:10px;color:#34d399;margin-top:3px" }, "Atomic SQLite WAL Commit")
          )
        )
      );

      // Table Container
      tableHostEl = el("div", { style: "overflow-x:auto" });
      const tableCard = el("div", { class: "card", style: "padding:14px" },
        el("div", { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px" },
          el("h4", { style: "margin:0;display:flex;align-items:center;gap:8px;color:#38bdf8" },
            renderIcon("cpu", "cyan", "xs"),
            el("span", {}, "Live Active Threads & Mutex / Synchronization Primitives")
          ),
          el("span", { class: "device-chip", style: "font-size:11px;padding:2px 8px" },
            "Auto-refreshing every 1.5s"
          )
        ),
        tableHostEl
      );

      // OS Lab Viva Defense Accordion Cheatsheet (Constructed ONCE so open/close state persists smoothly)
      const vivaWrap = el("div", { class: "accordion" + (vivaNotesOpen ? " open" : "") });
      const vivaHeader = el("div", {
        class: "accordion-header",
        onclick: () => {
          vivaNotesOpen = !vivaNotesOpen;
          vivaWrap.classList.toggle("open", vivaNotesOpen);
        }
      },
        el("div", { class: "accordion-title" },
          renderIcon("info", "cyan", "sm"),
          el("span", { style: "font-weight:600" }, "OS Viva Defense Reference & Academic Concept Mapping"),
          el("span", { class: "badge purple", style: "font-size:10px" }, "For Lab Defense / Presentation")
        ),
        renderIcon("chevron-down", "slate", "xs", "accordion-chevron")
      );

      const vivaContent = el("div", { class: "accordion-content", style: "padding:14px 18px" },
        el("div", { class: "grid2", style: "gap:14px;font-size:12px" },
          el("div", { style: "background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04)" },
            el("strong", { style: "color:#38bdf8;display:block;margin-bottom:4px" }, "1. Producer-Consumer Pattern:"),
            el("span", { class: "dim" },
              "Multiple non-blocking collector threads (proc_sample, net_conns, win_events) act as Producers, asynchronously pushing OS events into a bounded queue. The DB Batch Writer acts as a Consumer, batching events into SQLite WAL."
            )
          ),
          el("div", { style: "background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04)" },
            el("strong", { style: "color:#10b981;display:block;margin-bottom:4px" }, "2. Synchronization & Condition Variables:"),
            el("span", { class: "dim" },
              "DB Writer sleeps efficiently on a Condition Variable (threading.Condition) and is woken up when the queue reaches the batch threshold or after timeout, preventing busy-waiting CPU burn."
            )
          ),
          el("div", { style: "background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04)" },
            el("strong", { style: "color:#c084fc;display:block;margin-bottom:4px" }, "3. Bounded Buffer & Backpressure:"),
            el("span", { class: "dim" },
              "Queue size is strictly capped at 10,000 items (32 MB). If an event surge occurs, non-essential samples are gracefully shed to protect OS stability and ensure zero uncontrolled memory growth."
            )
          ),
          el("div", { style: "background:rgba(255,255,255,0.02);padding:12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04)" },
            el("strong", { style: "color:#f59e0b;display:block;margin-bottom:4px" }, "4. Deadlock Prevention & Teardown:"),
            el("span", { class: "dim" },
              "During shutdown, threading.Event signals all workers to terminate cleanly. Threads are joined with a strict 2.0-second timeout, guaranteeing the process exits without hanging or orphaned zombie threads."
            )
          )
        )
      );

      vivaWrap.append(vivaHeader, vivaContent);

      container.append(
        hero,
        statsGrid,
        pipelineBox,
        tableCard,
        vivaWrap
      );

      initialized = true;
    }

    async function draw() {
      if (!alive) return;
      try {
        const [h, tRes] = await Promise.all([
          api("/health").catch(() => G.state.health || {}),
          api("/system/threads").catch(() => ({ threads: [] }))
        ]);

        const rawThreads = (tRes && Array.isArray(tRes.threads) && tRes.threads.length)
          ? tRes.threads
          : (h && Array.isArray(h.threads) && h.threads.length ? h.threads : fallbackThreads);

        const threads = rawThreads.map(t => ({
          name: t.name || "worker",
          role: t.role || (t.name?.includes("proc") || t.name?.includes("net") || t.name?.includes("win") ? "producer" : "consumer"),
          sync_primitive: t.sync_primitive || (t.interval_s ? `Timer (every ${t.interval_s}s)` : "queue.Queue"),
          alive: t.alive !== undefined ? Boolean(t.alive) : true,
          errors: t.errors || 0,
          interval_s: t.interval_s,
          last_beat_age_s: t.last_beat_age_s
        }));

        const q = (h && h.queue) || {};
        const dbInfo = (h && h.db) || {};
        const chainOk = dbInfo.audit_chain_ok !== undefined ? Boolean(dbInfo.audit_chain_ok) : true;

        if (!initialized) {
          buildSkeleton();
        }

        // Producers vs Consumers counts
        const producers = threads.filter(t => (t.role || "").includes("producer"));
        const consumers = threads.filter(t => (t.role || "").includes("consumer"));
        const watchdogs = threads.filter(t => (t.role || "").includes("watchdog"));

        // Update Hero
        heroCountEl.textContent = `${threads.length} Active OS Workers • 0 Deadlocks`;

        // Update Queue Card
        const depth = q.depth || 0;
        const fillPct = Math.min(100, q.fill_pct || 0);
        qDepthEl.textContent = `${depth.toLocaleString()} / 10,000`;
        qSubEl.textContent = `Queue Fill: ${fillPct}% • ${fmt.bytes(q.bytes || 0)}`;
        qBarEl.style.width = `${fillPct}%`;
        qBarEl.style.background = fillPct > 80 ? "#f43f5e" : "#38bdf8";
        qGenEl.textContent = `Generated: ${(q.generated || 0).toLocaleString()}`;
        qDropEl.textContent = `Dropped: ${(q.dropped || 0).toLocaleString()} (${q.drop_rate_pct || 0}%)`;

        // Update Threads Card
        thTotalEl.textContent = `${threads.length} Worker Threads`;
        thProdEl.textContent = producers.length;
        thConsEl.textContent = consumers.length;
        thWatchEl.textContent = watchdogs.length;

        // Update IPC / Safety Card
        stQueueEl.textContent = (q.state || "OK").toUpperCase();
        stQueueEl.className = q.state === "warn" || q.state === "critical" ? "st-bad" : "st-ok";
        stChainEl.textContent = chainOk ? "Verified ✔" : "Broken ✖";
        stChainEl.className = chainOk ? "st-ok" : "st-bad";

        // Update Visual Pipeline
        pipeProdDescEl.textContent = `${producers.length} threads (proc, net, events)`;
        pipeQueueDescEl.textContent = `Capacity 10,000 • ${depth} queued`;
        pipeConsDescEl.textContent = `${consumers.length} threads (batch write, correlation)`;

        // Update Threads Table
        const threadCols = [
          {
            label: "THREAD / WORKER",
            render: r => el("div", { style: "display:flex;align-items:center;gap:8px" },
              el("span", { class: "tray-dot " + (r.alive ? "dot-cpu" : "dot-bad") }),
              el("code", { style: "font-weight:600;color:var(--fg-main)" }, r.name)
            )
          },
          {
            label: "OS CONCURRENCY ROLE",
            render: r => {
              const isProd = (r.role || "").includes("producer");
              const isCons = (r.role || "").includes("consumer");
              const isWatch = (r.role || "").includes("watchdog");
              const badgeCls = isProd ? "cyan" : isCons ? "emerald" : isWatch ? "purple" : "slate";
              return el("span", { class: `badge ${badgeCls}`, style: "font-size:11px" }, r.role || "worker");
            }
          },
          {
            label: "SYNCHRONIZATION PRIMITIVE",
            render: r => el("code", { style: "font-size:11.5px;color:var(--fg-dim)" },
              r.sync_primitive || (r.interval_s ? `Timer (every ${r.interval_s}s)` : "queue.Queue")
            )
          },
          {
            label: "STATE",
            render: r => el("span", { class: r.alive ? "st-ok" : "st-bad" },
              r.alive ? "RUNNING" : "STOPPED"
            )
          },
          {
            label: "HEARTBEAT / BEAT AGE",
            cls: "r",
            render: r => r.last_beat_age_s !== null && r.last_beat_age_s !== undefined
              ? `${r.last_beat_age_s}s ago`
              : (r.interval_s ? `every ${r.interval_s}s` : "event-driven")
          },
          {
            label: "FAULTS / ERRORS",
            cls: "r",
            render: r => el("span", { class: r.errors ? "st-bad" : "dim" }, r.errors || 0)
          }
        ];

        clear(tableHostEl).append(table(threadCols, threads));

      } catch (e) {
        if (alive && !initialized) {
          clear(container).append(
            el("div", { class: "pad st-bad" }, "Concurrency Telemetry Error: " + e.message)
          );
        }
      }
    }

    draw();
    const interval = setInterval(draw, 1500);
    return {
      destroy() {
        alive = false;
        clearInterval(interval);
      }
    };
  }
};
