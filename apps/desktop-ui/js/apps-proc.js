"use strict";
function download(name, obj) {
  const a = el("a", { href: URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" })), download: name });
  document.body.append(a); a.click(); a.remove();
}

G.apps.processes = {
  name: "Process Center", short: "procs", icon: "proc", w: 1080, h: 660, flush: true, title: h => `Guardian OS — Process Center (${h})`,
  mount(body) {
    const st = {
      viewMode: "graph", // "graph" (Falcon / EDR Visual Tree) or "table"
      filter: "all",     // "all", "alerts", "simulated", "high_mem"
      sort: "rss",
      order: "desc",
      q: "",
      sel: null,
      items: [],
      alive: true
    };
    const sorts = ["rss", "cpu", "pid", "name", "start_ts"];

    const search = el("input", {
      placeholder: "F3 search name / pid / path",
      style: "width:220px",
      oninput: e => { st.q = e.target.value; load(); }
    });

    const bars = el("span", { style: "display:flex;align-items:center;gap:10px;font-size:12px;color:var(--fg-dim)" });
    const mainArea = el("div", { style: "flex:1;display:flex;min-height:0;overflow:hidden;position:relative" });

    // Mode Toggle Buttons
    const btnGraph = el("button", {
      class: "btn-subtle xs" + (st.viewMode === "graph" ? " cyan" : ""),
      style: "font-weight:600;display:flex;align-items:center;gap:5px",
      onclick: () => setMode("graph")
    },
      renderIcon("hierarchy", st.viewMode === "graph" ? "cyan" : "slate", "xs"),
      el("span", {}, "Process Tree Graph (EDR)")
    );

    const btnTable = el("button", {
      class: "btn-subtle xs" + (st.viewMode === "table" ? " cyan" : ""),
      style: "font-weight:600;display:flex;align-items:center;gap:5px",
      onclick: () => setMode("table")
    },
      renderIcon("layers", st.viewMode === "table" ? "cyan" : "slate", "xs"),
      el("span", {}, "Process Table List")
    );

    function setMode(m) {
      st.viewMode = m;
      btnGraph.className = "btn-subtle xs" + (st.viewMode === "graph" ? " cyan" : "");
      btnTable.className = "btn-subtle xs" + (st.viewMode === "table" ? " cyan" : "");
      load();
    }

    const sortSel = el("select", {
      "aria-label": "sort",
      onchange: e => { st.sort = e.target.value; load(); }
    }, sorts.map(s => el("option", { value: s }, s)));

    const menubar = el("div", { class: "menubar", style: "gap:10px;padding:8px 12px" },
      btnGraph, btnTable,
      el("span", { style: "width:1px;height:18px;background:var(--border-light)" }),
      search,
      el("label", { style: "font-size:12px;display:flex;align-items:center;gap:6px" }, "Sort:", sortSel),
      el("span", { class: "sp" }),
      bars
    );

    const fkeys = el("div", { class: "fkeys" },
      ...[
        ["F3", "Search", () => search.focus()],
        ["F5", "View Mode", () => setMode(st.viewMode === "graph" ? "table" : "graph")],
        ["F6", "Sort", () => { st.sort = sorts[(sorts.indexOf(st.sort) + 1) % sorts.length]; sortSel.value = st.sort; load(); }],
        ["F9", "Terminate", () => {
          const r = st.items && st.items.find(x => x.key === st.sel);
          st.sel && respond("terminate", st.sel, r ? r.name : st.sel);
        }],
        ["F10", "Close", () => WM.close("processes")]
      ].map(([k, l, f]) => el("button", { onclick: f }, el("b", {}, k), l))
    );

    body.append(menubar, mainArea, fkeys);
    body.tabIndex = 0;
    body.addEventListener("keydown", e => {
      const m = { F3: 0, F5: 1, F6: 2, F9: 3, F10: 4 }[e.key];
      if (m !== undefined) { e.preventDefault(); fkeys.children[m].click(); }
    });

    // Helper: Build Tree Structure & Generations
    function buildGenerations(items) {
      const byKey = new Map(items.map(p => [p.key, p]));
      const byPid = new Map(items.map(p => [p.pid, p]));
      const kids = new Map();

      items.forEach(p => {
        let parentKey = null;
        if (p.parent_key && byKey.has(p.parent_key)) {
          parentKey = p.parent_key;
        } else if (p.ppid !== undefined && p.ppid !== null && byPid.has(p.ppid)) {
          const parent = byPid.get(p.ppid);
          if (parent && parent.key !== p.key) parentKey = parent.key;
        }
        (kids.get(parentKey) || kids.set(parentKey, []).get(parentKey)).push(p);
      });

      const generations = [];
      const assigned = new Set();

      function assignGen(p, gen) {
        if (assigned.has(p.key) || gen > 6) return;
        assigned.add(p.key);
        if (!generations[gen]) generations[gen] = [];
        generations[gen].push(p);
        const children = kids.get(p.key) || [];
        children.forEach(c => assignGen(c, gen + 1));
      }

      const roots = kids.get(null) || [];
      roots.forEach(r => assignGen(r, 0));
      items.forEach(p => {
        if (!assigned.has(p.key)) assignGen(p, 0);
      });

      return { generations, kids, byKey };
    }

    async function load() {
      if (!st.alive) return;
      try {
        const r = await api(`/processes?limit=1000&sort=${st.sort}&order=${st.order}&q=${encodeURIComponent(st.q)}`);
        st.items = r.items || [];
        const s = G.state.summary?.latest || {};
        clear(bars).append(
          el("span", {}, "CPU: "), bar(s.cpu, 10),
          el("span", { style: "margin-left:8px" }, "RAM: "), bar(s.mem, 10),
          el("span", { class: "badge slate", style: "margin-left:8px;font-size:11px" }, `${r.total} Active Tasks`)
        );

        if (!st.sel && st.items.length) {
          // Auto select first incident or first process
          const incProc = st.items.find(x => x.incident);
          st.sel = incProc ? incProc.key : st.items[0].key;
        }

        if (st.viewMode === "graph") {
          renderGraphView();
        } else {
          renderTableView();
        }
      } catch (e) {
        console.error("Process load failed:", e);
      }
    }

    // Render CrowdStrike Falcon / EDR Graph View (Matching Image 1)
    function renderGraphView() {
      let filtered = st.items;
      if (st.filter === "alerts") filtered = st.items.filter(x => x.incident);
      else if (st.filter === "simulated") filtered = st.items.filter(x => x.simulated);
      else if (st.filter === "high_mem") filtered = st.items.filter(x => (x.rss || 0) > 100 * 1024 * 1024);

      const alertCount = st.items.filter(x => x.incident).length;
      const simCount = st.items.filter(x => x.simulated).length;
      const { generations, kids } = buildGenerations(filtered.slice(0, 100));

      // Left Legend & Filter Sidebar
      const legend = el("div", { class: "edr-legend" },
        el("div", { class: "edr-legend-title" }, "Process Entities"),
        el("div", {
          class: "edr-legend-item" + (st.filter === "all" ? " on" : ""),
          onclick: () => { st.filter = "all"; renderGraphView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("layers", "cyan", "xs"),
            el("span", {}, "All Entities")
          ),
          el("span", { class: "device-chip", style: "font-size:10px" }, st.items.length)
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "alerts" ? " on" : ""),
          onclick: () => { st.filter = "alerts"; renderGraphView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            el("span", { class: "tray-dot dot-bad" }),
            el("span", {}, "Detections")
          ),
          el("span", { class: "badge rose", style: "font-size:10px" }, alertCount)
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "simulated" ? " on" : ""),
          onclick: () => { st.filter = "simulated"; renderGraphView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            el("span", { class: "tray-dot dot-mem" }),
            el("span", {}, "Simulated Scenarios")
          ),
          el("span", { class: "badge amber", style: "font-size:10px" }, simCount)
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "high_mem" ? " on" : ""),
          onclick: () => { st.filter = "high_mem"; renderGraphView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("activity", "purple", "xs"),
            el("span", {}, "High RAM (>100MB)")
          ),
          el("span", { class: "device-chip", style: "font-size:10px" }, st.items.filter(x => (x.rss || 0) > 100 * 1024 * 1024).length)
        ),

        el("div", { style: "border-top:1px solid var(--border-light);margin-top:6px;padding-top:10px" }),
        el("div", { class: "edr-legend-title" }, "Highlight Lineage"),
        el("div", { class: "dim", style: "font-size:11.5px;line-height:1.4" },
          "Click any node in the tree graph to trace its lineage, inspect PE Authenticode signer, view incident evidence, or execute response actions."
        )
      );

      // Center Canvas Container
      const canvasContainer = el("div", { class: "edr-canvas-container" });
      const canvasInner = el("div", { class: "edr-canvas-inner" });
      const svgLayer = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svgLayer.setAttribute("class", "edr-svg-layer");

      const nodesLayer = el("div", { class: "edr-nodes-layer" });
      const nodeElements = new Map();

      // Render columns for each generation
      generations.forEach((genProcs, colIdx) => {
        const colEl = el("div", { class: "edr-column" });
        genProcs.forEach(proc => {
          const hasInc = Boolean(proc.incident);
          const isSelected = proc.key === st.sel;
          const children = kids.get(proc.key) || [];

          const node = el("div", {
            class: `edr-node ${hasInc ? "has-incident" : ""} ${isSelected ? "selected" : ""}`.trim(),
            dataset: { key: proc.key },
            onclick: () => select(proc.key)
          },
            el("div", { class: "edr-node-head" },
              el("span", { class: `tray-dot ${hasInc ? "dot-bad" : proc.simulated ? "dot-mem" : "dot-cpu"}` }),
              el("span", { class: "edr-node-name", title: proc.name }, proc.name),
              hasInc ? el("span", { class: "badge rose", style: "font-size:9.5px;padding:1px 5px" }, "ALERT") : null,
              proc.simulated ? el("span", { class: "badge amber", style: "font-size:9.5px;padding:1px 5px" }, "SIM") : null
            ),
            el("div", { class: "edr-node-meta" },
              el("span", {}, `PID: ${proc.pid}`),
              el("span", {}, fmt.bytes(proc.rss))
            ),
            children.length ? el("div", { style: "display:flex;align-items:center;justify-content:space-between;margin-top:2px" },
              el("span", { class: "dim", style: "font-size:10.5px" }, `${children.length} spawned`),
              el("span", { style: "color:var(--primary);font-size:11px" }, "→")
            ) : null
          );

          colEl.append(node);
          nodeElements.set(proc.key, node);
        });
        nodesLayer.append(colEl);
      });

      canvasInner.append(svgLayer, nodesLayer);
      canvasContainer.append(canvasInner);

      // Draw SVG Connection Curves
      function drawLinks() {
        while (svgLayer.firstChild) svgLayer.removeChild(svgLayer.firstChild);
        const rectInner = canvasInner.getBoundingClientRect();
        svgLayer.setAttribute("width", canvasInner.scrollWidth);
        svgLayer.setAttribute("height", canvasInner.scrollHeight);

        generations.forEach(genProcs => {
          genProcs.forEach(p => {
            const parentNode = nodeElements.get(p.key);
            if (!parentNode) return;
            const pRect = parentNode.getBoundingClientRect();
            const px = pRect.right - rectInner.left;
            const py = pRect.top + pRect.height / 2 - rectInner.top;

            const children = kids.get(p.key) || [];
            children.forEach(c => {
              const childNode = nodeElements.get(c.key);
              if (!childNode) return;
              const cRect = childNode.getBoundingClientRect();
              const cx = cRect.left - rectInner.left;
              const cy = cRect.top + cRect.height / 2 - rectInner.top;

              const isHighlighted = (p.key === st.sel || c.key === st.sel);
              const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
              const dx = (cx - px) * 0.5;
              const d = `M ${px} ${py} C ${px + dx} ${py}, ${cx - dx} ${cy}, ${cx} ${cy}`;
              path.setAttribute("d", d);
              path.setAttribute("fill", "none");
              path.setAttribute("stroke", isHighlighted ? (c.incident ? "#f43f5e" : "#38bdf8") : "rgba(255, 255, 255, 0.15)");
              path.setAttribute("stroke-width", isHighlighted ? "2.5" : "1.5");
              if (isHighlighted) path.setAttribute("stroke-dasharray", "none");
              svgLayer.append(path);
            });
          });
        });
      }

      setTimeout(drawLinks, 40);

      // Right Details Inspector
      const inspector = el("div", { class: "edr-inspector" });
      renderInspectorContent(inspector);

      clear(mainArea).append(legend, canvasContainer, inspector);
    }

    // Render Detailed Table View
    function renderTableView() {
      const tblContainer = el("div", { style: "flex:1;overflow:auto;display:flex;flex-direction:column" });
      const tbl = el("div", { style: "flex:1;overflow:auto" });
      const detail = el("div", { class: "edr-inspector", style: "width:340px" });

      clear(tbl).append(table([
        { label: "PID", cls: "r", w: "70px", render: r => r.pid },
        { label: "PPID", cls: "r dim", w: "70px", render: r => r.ppid },
        { label: "CPU%", cls: "r", render: r => (r.cpu || 0).toFixed(1) },
        { label: "MEM", cls: "r", render: r => fmt.bytes(r.rss) },
        { label: "SIGNER", render: r => el("span", { class: r.signer === "unsigned" ? "st-degraded" : "dim" }, r.signer || "?") },
        { label: "INC", render: r => r.incident ? sevChip(r.incident) : "" },
        {
          label: "PROCESS NAME",
          render: r => el("span", { style: "font-weight:600" },
            r.name,
            r.simulated ? el("span", { class: "badge amber", style: "font-size:9.5px;margin-left:6px" }, "SIM") : null
          )
        },
        { label: "PATH", render: r => el("span", { class: "dim", style: "font-size:12px" }, fmt.short(r.exe, 60)) },
      ],
        st.items,
        {
          onRow: r => select(r.key),
          selected: r => r.key === st.sel
        }
      ));

      renderInspectorContent(detail);
      tblContainer.append(tbl);
      clear(mainArea).append(tblContainer, detail);
    }

    async function select(key) {
      st.sel = key;
      if (st.viewMode === "graph") {
        renderGraphView();
      } else {
        renderTableView();
      }
    }

    // Render Inspector Sidebar matching Image 1
    async function renderInspectorContent(container) {
      if (!st.sel) {
        clear(container).append(el("div", { class: "dim", style: "padding:20px;text-align:center" }, "Select a process to inspect"));
        return;
      }
      try {
        const d = await api("/processes/" + encodeURIComponent(st.sel));
        const p = d.process;

        const head = el("div", {},
          el("div", { style: "display:flex;align-items:center;justify-content:space-between" },
            el("h3", { style: "margin:0;font-size:16px;color:#fff;display:flex;align-items:center;gap:8px" },
              renderIcon("proc", "cyan", "xs"),
              p.name
            ),
            el("span", { class: "device-chip", style: "font-size:11px" }, `PID ${p.pid}`)
          ),
          el("div", { style: "margin-top:6px" },
            d.detections && d.detections.length
              ? el("div", { class: "badge rose", style: "font-size:11px;padding:3px 8px;display:inline-flex;align-items:center;gap:6px" },
                renderIcon("shield-alert", "rose", "xs"),
                `Detection — High Risk (${d.detections.length} matched)`
              )
              : el("div", { class: "badge emerald", style: "font-size:11px;padding:3px 8px;display:inline-flex;align-items:center;gap:6px" },
                renderIcon("shield-check", "emerald", "xs"),
                "Normal Process Activity"
              )
          )
        );

        const props = el("div", { style: "display:flex;flex-direction:column;gap:6px;font-size:12px" },
          el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Parent Process:"), el("strong", {}, `${p.parent_name || "?"} (PID ${p.ppid})`)),
          el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Authenticode Signer:"), el("span", { class: p.signer === "unsigned" ? "st-warn" : "st-ok" }, p.signer || "unsigned")),
          el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Memory RSS:"), el("strong", {}, fmt.bytes(p.rss))),
          el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "CPU Usage:"), el("strong", {}, `${(p.cpu || 0).toFixed(1)}%`)),
          el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Started:"), el("span", {}, fmt.datetime(p.start_ts))),
          el("div", { style: "margin-top:4px" },
            el("span", { class: "dim", style: "display:block;margin-bottom:2px" }, "Executable Path:"),
            el("code", { style: "font-size:11px;word-break:break-all;color:var(--fg-main)" }, p.exe || "n/a")
          ),
          el("div", { style: "margin-top:4px" },
            el("span", { class: "dim", style: "display:block;margin-bottom:2px" }, "Command Line:"),
            el("code", { style: "font-size:11px;word-break:break-all;color:var(--fg-dim)" }, p.cmdline || "n/a")
          )
        );

        // Security Intelligence & Detections
        const intel = el("div", { style: "border-top:1px solid var(--border-light);padding-top:10px" },
          el("h4", { style: "margin:0 0 8px 0;font-size:13px;color:#38bdf8;display:flex;align-items:center;gap:6px" },
            renderIcon("shield", "cyan", "xs"),
            "Security Intelligence & Rule Hits:"
          ),
          (d.detections && d.detections.length)
            ? el("div", { style: "display:flex;flex-direction:column;gap:6px" },
              ...d.detections.map(det => el("div", { style: "background:rgba(244,63,94,0.1);padding:6px 8px;border-radius:6px;border-left:3px solid #f43f5e" },
                el("div", { style: "font-weight:600;color:#fda4af;font-size:12px" }, `[${det.evidence_class}] ${det.title}`),
                el("div", { class: "dim", style: "font-size:11px;margin-top:2px" }, det.caveat || "Suspicious behavioral correlation observed.")
              ))
            )
            : el("div", { class: "dim", style: "font-size:12px" }, "No active threat incidents detected for this process.")
        );

        // Child Processes
        const childBox = el("div", { style: "border-top:1px solid var(--border-light);padding-top:10px" },
          el("h4", { style: "margin:0 0 6px 0;font-size:13px;color:var(--fg-main)" }, `Spawned Child Processes (${(d.children || []).length}):`),
          (d.children && d.children.length)
            ? el("div", { style: "display:flex;flex-wrap:wrap;gap:5px" },
              ...d.children.map(c => el("button", {
                class: "btn-subtle xs cyan",
                style: "font-size:11px;padding:3px 7px",
                onclick: () => select(c.key)
              }, `→ [PID ${c.pid}] ${c.name}`))
            )
            : el("div", { class: "dim", style: "font-size:11.5px" }, "No child processes spawned.")
        );

        // Quick Actions
        const actions = el("div", { style: "border-top:1px solid var(--border-light);padding-top:12px;display:flex;flex-direction:column;gap:6px" },
          el("button", {
            class: "btn-subtle sm rose",
            style: "width:100%;font-weight:600;display:flex;align-items:center;justify-content:center;gap:6px",
            onclick: () => respond("terminate", st.sel, p.name)
          }, "⏹ Terminate Process (F9)"),
          el("div", { style: "display:flex;gap:6px" },
            el("button", {
              class: "btn-subtle xs",
              style: "flex:1",
              onclick: () => respond("suspend", st.sel, p.name)
            }, "⏸ Suspend"),
            el("button", {
              class: "btn-subtle xs",
              style: "flex:1",
              onclick: () => respond("resume", st.sel, p.name)
            }, "▶ Resume")
          ),
          el("div", { style: "display:flex;gap:6px" },
            p.exe ? el("button", {
              class: "btn-subtle xs cyan",
              style: "flex:1",
              onclick: () => {
                const scanWin = WM.open("models");
                setTimeout(() => {
                  const inp = $("#windows input[aria-label='file path']");
                  if (inp) {
                    inp.value = p.exe;
                    const btn = inp.nextElementSibling;
                    if (btn) btn.click();
                  }
                }, 100);
              }
            }, "🔍 Inspect File") : null,
            p.sha256 ? el("button", {
              class: "btn-subtle xs emerald",
              style: "flex:1",
              onclick: () => allow("sha256", p.sha256)
            }, "🛡 Allowlist Hash") : null
          )
        );

        clear(container).append(head, props, intel, childBox, actions);
      } catch (err) {
        clear(container).append(el("div", { class: "pad st-bad" }, "Inspector error: " + err.message));
      }
    }

    async function allow(kind, value) {
      confirmDialog({
        title: `Add ${kind.toUpperCase()} to Allowlist`,
        message: `This will suppress security detections matching this ${kind}. The action is logged to the tamper-evident audit chain.`,
        confirmPrompt: "Reason for allowlisting (required for audit log):",
        placeholder: "e.g. Approved developer build / internal IT administration tool",
        onConfirm: async (reason) => {
          if (!reason) return;
          try {
            await api("/allowlist", { method: "POST", body: { kind, value, reason } });
            toast(`Added ${kind} to allowlist`, "low");
          } catch (e) {
            toast(e.message, "high");
          }
        }
      });
    }

    load();
    const interval = setInterval(load, 3000);
    return {
      destroy() {
        st.alive = false;
        clearInterval(interval);
      },
      onFocus() { }
    };
  }
};
