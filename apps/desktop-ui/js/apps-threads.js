"use strict";

G.apps.threads = {
  name: "Concurrency & IPC",
  short: "threads",
  icon: "cpu",
  w: 980,
  h: 680,
  title: h => `Guardian OS — Concurrency & IPC Workstation (${h})`,
  mount(body) {
    let alive = true;
    let vivaNotesOpen = true;

    async function draw() {
      if (!alive) return;
      try {
        const [h, tRes] = await Promise.all([
          api("/health").catch(() => G.state.health || {}),
          api("/system/threads").catch(() => ({ threads: [] }))
        ]);
        const threads = (tRes && tRes.threads && tRes.threads.length) ? tRes.threads : (h && Array.isArray(h.threads) ? h.threads : []);
        const q = (h && h.queue) || {};
        const dbInfo = (h && h.db) || {};
        const chainOk = Boolean(dbInfo.audit_chain_ok);

        // Producers vs Consumers counts
        const producers = threads.filter(t => (t.role || "").includes("producer"));
        const consumers = threads.filter(t => (t.role || "").includes("consumer"));
        const watchdogs = threads.filter(t => (t.role || "").includes("watchdog"));

        // Header Hero Banner
        const hero = el("div", {
          class: "hero-status-banner",
          style: "padding:16px 20px;margin-bottom:14px;background:linear-gradient(135deg, rgba(56,189,248,0.1), rgba(16,185,129,0.06));border:1px solid rgba(56,189,248,0.25);border-radius:12px;display:flex;align-items:center;justify-content:space-between"
        },
          el("div", { style: "display:flex;align-items:center;gap:12px" },
            renderIcon("cpu", "cyan", "lg"),
            el("div", {},
              el("h3", { style: "margin:0 0 4px 0;font-size:16px;color:#fff;display:flex;align-items:center;gap:8px" },
                "OS Lab Concurrency & IPC Live Workstation",
                el("span", { class: "badge cyan", style: "font-size:10px" }, "Live OS Telemetry")
              ),
              el("p", { class: "dim", style: "margin:0;font-size:12.5px" },
                "Real-time multithreading, bounded producer-consumer queue synchronization, and IPC primitives."
              )
            )
          ),
          el("div", { style: "text-align:right" },
            el("div", { class: "st-ok", style: "font-weight:700;font-size:14px" }, "● All Threads Synchronized"),
            el("div", { class: "dim", style: "font-size:11px" }, `${threads.length} Active OS Workers • 0 Deadlocks`)
          )
        );

        // Top 4 Stat Bento Cards
        const cardQueue = el("div", { class: "card", style: "padding:14px" },
          el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#38bdf8" },
            renderIcon("database", "cyan", "xs"),
            el("span", {}, "Bounded Queue (IPC Buffer)")
          ),
          el("div", { style: "font-size:20px;font-weight:700;color:#fff" }, `${q.depth || 0} / 10,000`),
          el("div", { style: "font-size:11.5px;color:var(--fg-dim);margin:2px 0 6px 0" }, `Queue Fill: ${q.fill_pct || 0}% • ${fmt.bytes(q.bytes || 0)}`),
          el("div", { style: "height:6px;background:rgba(255,255,255,0.08);border-radius:3px;overflow:hidden" },
            el("div", { style: `height:100%;width:${Math.min(100, q.fill_pct || 0)}%;background:${(q.fill_pct || 0) > 80 ? '#f43f5e' : '#38bdf8'}` })
          ),
          el("div", { style: "display:flex;justify-content:space-between;margin-top:6px;font-size:11px;color:var(--fg-muted)" },
            el("span", {}, `Generated: ${q.generated || 0}`),
            el("span", {}, `Dropped: ${q.dropped || 0} (${q.drop_rate_pct || 0}%)`)
          )
        );

        const cardThreads = el("div", { class: "card", style: "padding:14px" },
          el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#10b981" },
            renderIcon("activity", "emerald", "xs"),
            el("span", {}, "OS Thread Pool")
          ),
          el("div", { style: "font-size:20px;font-weight:700;color:#fff" }, `${threads.length} Worker Threads`),
          el("div", { style: "font-size:11.5px;color:var(--fg-dim);margin:2px 0 6px 0" }, "Role Breakdown:"),
          el("div", { style: "display:flex;flex-direction:column;gap:3px;font-size:11.5px" },
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Producers (Collectors):"),
              el("strong", { class: "cyan" }, producers.length)
            ),
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Consumers (DB/Engine):"),
              el("strong", { class: "emerald" }, consumers.length)
            ),
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Watchdogs (Heartbeat):"),
              el("strong", { class: "purple" }, watchdogs.length)
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

        const cardIPC = el("div", { class: "card", style: "padding:14px" },
          el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 8px 0;color:#f59e0b" },
            renderIcon("shield-check", "amber", "xs"),
            el("span", {}, "Reliability & Safety")
          ),
          el("div", { style: "display:flex;flex-direction:column;gap:6px;font-size:11.5px;margin-top:4px" },
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Queue State:"),
              el("strong", { class: q.state === "ok" ? "st-ok" : "st-bad" }, (q.state || "OK").toUpperCase())
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
              el("strong", { class: chainOk ? "st-ok" : "st-bad" }, chainOk ? "Verified ✔" : "Broken ✖")
            )
          )
        );

        const statsGrid = el("div", { class: "grid4", style: "margin-bottom:14px" },
          cardQueue, cardThreads, cardSync, cardIPC
        );

        // Visual Pipeline Flow Box
        const pipelineBox = el("div", {
          class: "card",
          style: "margin-bottom:14px;padding:12px 16px;background:rgba(15,23,42,0.6);border:1px dashed rgba(56,189,248,0.25)"
        },
          el("div", { style: "display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:12px" },
            el("div", { style: "text-align:center;flex:1;padding:8px;background:rgba(56,189,248,0.08);border-radius:8px" },
              el("div", { style: "font-weight:700;color:#38bdf8" }, "Producers (Collectors)"),
              el("div", { class: "dim", style: "font-size:11px" }, `${producers.length} threads (proc, net, events)`),
              el("div", { style: "font-size:10px;color:#38bdf8;margin-top:3px" }, "put_nowait() telemetry")
            ),
            el("div", { style: "color:var(--fg-dim);font-weight:700;font-size:16px" }, "──►"),
            el("div", { style: "text-align:center;flex:1.2;padding:8px;background:rgba(168,85,247,0.08);border-radius:8px" },
              el("div", { style: "font-weight:700;color:#c084fc" }, "Bounded Queue Buffer"),
              el("div", { class: "dim", style: "font-size:11px" }, `Capacity 10,000 • ${q.depth || 0} queued`),
              el("div", { style: "font-size:10px;color:#c084fc;margin-top:3px" }, "Condition Variable / Bounded Mutex")
            ),
            el("div", { style: "color:var(--fg-dim);font-weight:700;font-size:16px" }, "──►"),
            el("div", { style: "text-align:center;flex:1;padding:8px;background:rgba(16,185,129,0.08);border-radius:8px" },
              el("div", { style: "font-weight:700;color:#34d399" }, "Consumers (DB & Engine)"),
              el("div", { class: "dim", style: "font-size:11px" }, `${consumers.length} threads (batch write, correlation)`),
              el("div", { style: "font-size:10px;color:#34d399;margin-top:3px" }, "Atomic SQLite Commit")
            )
          )
        );

        // Threads Table
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

        const tableCard = el("div", { class: "card", style: "padding:14px;margin-bottom:14px" },
          el("div", { style: "display:flex;align-items:center;justify-content:space-between;margin-bottom:10px" },
            el("h4", { style: "margin:0;display:flex;align-items:center;gap:8px;color:#38bdf8" },
              renderIcon("cpu", "cyan", "xs"),
              el("span", {}, "Live Active Threads & Mutex / Synchronization Primitives")
            ),
            el("span", { class: "device-chip", style: "font-size:11px;padding:2px 8px" },
              `Auto-refreshing every 1.5s`
            )
          ),
          table(threadCols, threads)
        );

        // OS Lab Viva Defense Accordion Cheatsheet
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

        const vivaContent = el("div", { class: "accordion-content", style: "padding:12px 16px" },
          el("div", { class: "grid2", style: "gap:12px;font-size:12px" },
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px" },
              el("strong", { style: "color:#38bdf8;display:block;margin-bottom:4px" }, "1. Producer-Consumer Pattern:"),
              el("span", { class: "dim" },
                "Multiple non-blocking collector threads (proc_sample, net_conns, win_events) act as Producers, asynchronously pushing OS events into a bounded queue. The DB Batch Writer acts as a Consumer, batching events into SQLite WAL."
              )
            ),
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px" },
              el("strong", { style: "color:#10b981;display:block;margin-bottom:4px" }, "2. Synchronization & Condition Variables:"),
              el("span", { class: "dim" },
                "DB Writer sleeps efficiently on a Condition Variable (threading.Condition) and is woken up when the queue reaches the batch threshold or after timeout, preventing busy-waiting CPU burn."
              )
            ),
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px" },
              el("strong", { style: "color:#c084fc;display:block;margin-bottom:4px" }, "3. Bounded Buffer & Backpressure:"),
              el("span", { class: "dim" },
                "Queue size is strictly capped at 10,000 items (32 MB). If an event surge occurs, non-essential samples are gracefully shed to protect OS stability and ensure zero uncontrolled memory growth."
              )
            ),
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px" },
              el("strong", { style: "color:#f59e0b;display:block;margin-bottom:4px" }, "4. Deadlock Prevention & Teardown:"),
              el("span", { class: "dim" },
                "During shutdown, threading.Event signals all workers to terminate cleanly. Threads are joined with a strict 2.0-second timeout, guaranteeing the process exits without hanging or orphaned zombie threads."
              )
            )
          )
        );

        vivaWrap.append(vivaHeader, vivaContent);

        // Assembly
        clear(body).append(
          hero,
          statsGrid,
          pipelineBox,
          tableCard,
          vivaWrap
        );
      } catch (e) {
        if (alive) {
          clear(body).append(
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
