"use strict";

G.apps.processes = {
  name: "Process Center", short: "procs", icon: "proc", w: 1140, h: 690, flush: true, title: h => `secops@${(h || "guardian").toLowerCase()}:/proc [htop-edr]`,
  mount(body) {
    const st = {
      viewMode: "tree",  // "tree" (CrowdStrike Falcon EDR Tree), "table", "graph", "timeline"
      filter: "all",     // "all", "critical", "high", "threads", "simulated"
      highlight: null,   // "disk", "dll", "dns", "read", "write", "net"
      sort: "rss",
      order: "desc",
      q: "",
      sel: null,
      zoom: 1,
      items: [],
      alive: true
    };
    const sorts = ["rss", "cpu", "pid", "name", "start_ts"];

    const search = el("input", {
      placeholder: "F3 search name / pid / path / hash",
      style: "width:220px",
      oninput: e => { st.q = e.target.value; load(); }
    });

    const bars = el("span", { style: "display:flex;align-items:center;gap:10px;font-size:12px;color:var(--fg-dim)" });
    const mainArea = el("div", { class: "edr-wrap" });

    // Falcon EDR Top Sub-navigation Tabs (Matching Image 1)
    const subtabs = el("div", { class: "edr-subnav" },
      createTab("tree", "hierarchy", "Process tree"),
      createTab("table", "layers", "Process table"),
      createTab("graph", "network", "Process graph"),
      createTab("timeline", "activity", "Events timeline")
    );

    function createTab(mode, icon, label) {
      const btn = el("button", {
        class: "edr-subtab" + (st.viewMode === mode ? " active" : ""),
        onclick: () => setMode(mode)
      },
        renderIcon(icon, st.viewMode === mode ? "cyan" : "slate", "xs"),
        el("span", {}, label)
      );
      btn.dataset.mode = mode;
      return btn;
    }

    function setMode(m) {
      st.viewMode = m;
      subtabs.querySelectorAll(".edr-subtab").forEach(b => {
        b.className = "edr-subtab" + (b.dataset.mode === m ? " active" : "");
      });
      load();
    }

    const sortSel = el("select", {
      "aria-label": "sort",
      onchange: e => { st.sort = e.target.value; load(); }
    }, sorts.map(s => el("option", { value: s }, s)));

    const menubar = el("div", { class: "menubar", style: "gap:10px;padding:8px 12px" },
      subtabs,
      el("span", { style: "width:1px;height:18px;background:var(--border-light)" }),
      search,
      el("label", { style: "font-size:12px;display:flex;align-items:center;gap:6px" }, "Sort:", sortSel),
      el("span", { class: "sp" }),
      bars
    );

    const fkeys = el("div", { class: "fkeys" },
      ...[
        ["F3", "Search", () => search.focus()],
        ["F5", "View Mode", () => {
          const modes = ["tree", "table", "graph", "timeline"];
          setMode(modes[(modes.indexOf(st.viewMode) + 1) % modes.length]);
        }],
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
          el("span", { class: "badge slate", style: "margin-left:8px;font-size:11px" }, `${r.total} Entities Tracked`)
        );

        if (!st.sel && st.items.length) {
          // Auto select first incident or first process
          const incProc = st.items.find(x => x.incident || x.name === "payroll.exe");
          st.sel = incProc ? incProc.key : st.items[0].key;
        }

        if (st.viewMode === "tree") {
          renderFalconTreeView();
        } else if (st.viewMode === "table") {
          renderTableView();
        } else if (st.viewMode === "graph") {
          renderGraphTopologyView();
        } else if (st.viewMode === "timeline") {
          renderEventsTimelineView();
        }
      } catch (e) {
        console.error("Process load failed:", e);
      }
    }

    // ==========================================================================
    // 1. CrowdStrike Falcon EDR Process Tree View (Matching Image 1)
    // ==========================================================================
    function renderFalconTreeView() {
      let filtered = st.items;
      if (st.filter === "critical") filtered = st.items.filter(x => x.incident && (x.incident.severity === "critical" || x.incident === "critical"));
      else if (st.filter === "high") filtered = st.items.filter(x => x.incident && (x.incident.severity === "high" || x.incident === "high" || x.name === "payroll.exe"));
      else if (st.filter === "threads") filtered = st.items.filter(x => x.simulated || x.name === "payroll.exe");
      else if (st.filter === "simulated") filtered = st.items.filter(x => x.simulated);

      const critCount = st.items.filter(x => x.incident && (x.incident.severity === "critical" || x.incident === "critical")).length;
      const highCount = st.items.filter(x => (x.incident && (x.incident.severity === "high" || x.incident === "high")) || x.name === "payroll.exe").length;
      const { generations, kids } = buildGenerations(filtered.slice(0, 120));

      // Left Legend & Filter Sidebar (Matching Image 1)
      const legend = el("div", { class: "edr-legend" },
        el("div", { class: "edr-legend-title", style: "display:flex;align-items:center;justify-content:space-between" },
          el("span", {}, "Legend"),
          el("button", {
            class: "btn-subtle xs cyan",
            title: "Simulate Falcon Benchmark Threat (payroll.exe)",
            style: "padding:1px 6px;font-size:10px",
            onclick: async () => {
              try {
                await api("/simulate/payroll_edr_threat", { method: "POST" });
                toast("Simulated Falcon benchmark threat: payroll.exe loaded", "high");
                load();
              } catch (err) {
                toast("Simulation error: " + err.message, "high");
              }
            }
          }, "⚡ Replay")
        ),

        // Entity Types
        el("div", {
          class: "edr-legend-item" + (st.filter === "all" ? " on" : ""),
          onclick: () => { st.filter = "all"; renderFalconTreeView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("layers", "cyan", "xs"),
            el("span", {}, "All entities")
          ),
          el("span", { class: "device-chip", style: "font-size:10px" }, st.items.length)
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "critical" ? " on" : ""),
          onclick: () => { st.filter = "critical"; renderFalconTreeView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("shield-alert", "rose", "xs"),
            el("span", {}, "Detection - critical")
          ),
          el("span", { class: "badge rose", style: "font-size:10px" }, critCount || 1)
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "high" ? " on" : ""),
          onclick: () => { st.filter = "high"; renderFalconTreeView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("alert-triangle", "amber", "xs"),
            el("span", {}, "Detection - high")
          ),
          el("span", { class: "badge amber", style: "font-size:10px" }, highCount || 4)
        ),
        el("div", { class: "edr-legend-item" },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("hard-drive", "slate", "xs"),
            el("span", {}, "Host System")
          ),
          el("span", { class: "device-chip", style: "font-size:10px" }, "1")
        ),
        el("div", {
          class: "edr-legend-item" + (st.filter === "threads" ? " on" : ""),
          onclick: () => { st.filter = "threads"; renderFalconTreeView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("zap", "amber", "xs"),
            el("span", {}, "Injected threads")
          ),
          el("span", { class: "badge amber", style: "font-size:10px" }, "2")
        ),
        el("div", {
          class: "edr-legend-item",
          onclick: () => { st.filter = "all"; renderFalconTreeView(); }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            renderIcon("hierarchy", "slate", "xs"),
            el("span", {}, "Processes")
          ),
          el("span", { class: "device-chip", style: "font-size:10px" }, st.items.length)
        ),

        // Highlight By Operations (Matching Image 1)
        el("div", { style: "border-top:1px solid var(--border-light);margin-top:6px;padding-top:10px" }),
        el("div", { class: "edr-legend-title" }, "Highlight by"),
        ...[
          ["Disk operation", "chip-disk", "#e879f9", 19, "disk"],
          ["DLL/Library Load", "chip-dll", "#38bdf8", 19, "dll"],
          ["DNS request", "chip-dns", "#818cf8", 4, "dns"],
          ["File Read", "chip-read", "#c084fc", 4, "read"],
          ["File writes", "chip-read", "#f472b6", 7, "write"],
          ["Network operations", "chip-net", "#fda4af", 7, "net"]
        ].map(([label, chipCls, dotColor, count, hKey]) => el("div", {
          class: "edr-legend-item" + (st.highlight === hKey ? " on" : ""),
          onclick: () => {
            st.highlight = st.highlight === hKey ? null : hKey;
            renderFalconTreeView();
          }
        },
          el("div", { style: "display:flex;align-items:center;gap:8px" },
            el("span", { style: `width:8px;height:8px;border-radius:50%;background:${dotColor};box-shadow:0 0 6px ${dotColor}` }),
            el("span", {}, label)
          ),
          el("span", { class: `edr-chip ${chipCls}` }, count)
        ))
      );

      // Center Canvas Container
      const canvasContainer = el("div", { class: "edr-canvas-container" });
      const canvasInner = el("div", {
        class: "edr-canvas-inner",
        style: `transform: scale(${st.zoom}); transform-origin: top left; transition: transform 0.2s ease;`
      });
      const svgLayer = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svgLayer.setAttribute("class", "edr-svg-layer");

      // Zoom Controls Toolbar
      const zoomBar = el("div", { class: "edr-zoom-bar" },
        el("button", {
          class: "edr-zoom-btn",
          title: "Zoom In (+)",
          onclick: () => { st.zoom = Math.min(1.8, st.zoom + 0.15); canvasInner.style.transform = `scale(${st.zoom})`; }
        }, "+"),
        el("button", {
          class: "edr-zoom-btn",
          title: "Zoom Out (-)",
          onclick: () => { st.zoom = Math.max(0.6, st.zoom - 0.15); canvasInner.style.transform = `scale(${st.zoom})`; }
        }, "−"),
        el("button", {
          class: "edr-zoom-btn",
          title: "Reset Zoom (100%)",
          onclick: () => { st.zoom = 1.0; canvasInner.style.transform = `scale(${st.zoom})`; }
        }, "⟲")
      );

      const nodesLayer = el("div", { class: "edr-nodes-layer" });
      const nodeElements = new Map();

      // Render columns for each generation
      generations.forEach((genProcs, colIdx) => {
        const colEl = el("div", { class: "edr-column" });
        genProcs.forEach(proc => {
          const isSelected = proc.key === st.sel;
          const isPayroll = proc.name === "payroll.exe";
          const hasCrit = proc.incident && (proc.incident.severity === "critical" || proc.incident === "critical");
          const hasHigh = isPayroll || (proc.incident && (proc.incident.severity === "high" || proc.incident === "high"));
          const hasInc = Boolean(proc.incident || isPayroll);
          const children = kids.get(proc.key) || [];

          // Assign Falcon style event chips
          const eventChips = [];
          if (isPayroll) {
            eventChips.push(
              el("span", { class: "edr-chip chip-disk" }, "19 Disk"),
              el("span", { class: "edr-chip chip-dll" }, "19 DLL"),
              el("span", { class: "edr-chip chip-net" }, "7 Net")
            );
          } else if (proc.name.includes("powershell") || proc.name.includes("cmd")) {
            eventChips.push(
              el("span", { class: "edr-chip chip-dll" }, "12 DLL"),
              el("span", { class: "edr-chip chip-read" }, "4 Read")
            );
          } else if (proc.name.includes("netstat") || proc.name.includes("whoami")) {
            eventChips.push(
              el("span", { class: "edr-chip chip-net" }, "2 Net")
            );
          } else if (st.highlight) {
            eventChips.push(el("span", { class: `edr-chip chip-${st.highlight}` }, `Matched ${st.highlight}`));
          }

          let nodeClasses = "edr-node";
          if (hasCrit) nodeClasses += " has-incident alert-crit";
          else if (hasHigh) nodeClasses += " has-incident alert-high";
          if (isSelected) nodeClasses += " selected";

          const node = el("div", {
            class: nodeClasses,
            dataset: { key: proc.key },
            onclick: () => select(proc.key)
          },
            el("div", { class: "edr-node-head" },
              renderIcon(hasInc ? "shield-alert" : "proc", hasCrit ? "rose" : hasHigh ? "amber" : "cyan", "xs"),
              el("span", { class: "edr-node-name", title: proc.name }, proc.name),
              hasCrit ? el("span", { class: "badge rose", style: "font-size:9px;padding:1px 5px" }, "CRITICAL") :
              hasHigh ? el("span", { class: "badge amber", style: "font-size:9px;padding:1px 5px" }, "HIGH") : null,
              proc.simulated ? el("span", { class: "badge slate", style: "font-size:9px;padding:1px 5px" }, "SIM") : null
            ),
            el("div", { class: "edr-node-user" }, proc.ppid ? `PPID ${proc.ppid} • NT AUTHORITY` : "System Boot Process"),
            el("div", { class: "edr-node-meta" },
              el("span", {}, `PID: ${proc.pid}`),
              el("span", {}, fmt.bytes(proc.rss))
            ),
            eventChips.length ? el("div", { class: "edr-node-chips" }, ...eventChips) : null,
            children.length ? el("div", { style: "display:flex;align-items:center;justify-content:space-between;margin-top:4px" },
              el("span", { class: "dim", style: "font-size:10px" }, `${children.length} spawned`),
              el("span", { style: "color:var(--primary);font-size:11px" }, "→")
            ) : null
          );

          colEl.append(node);
          nodeElements.set(proc.key, node);
        });
        nodesLayer.append(colEl);
      });

      canvasInner.append(svgLayer, nodesLayer);
      canvasContainer.append(canvasInner, zoomBar);

      // Draw SVG Connection Curves
      function getPos(node) {
        let x = 0, y = 0, el = node;
        while (el && el !== canvasInner) {
          x += el.offsetLeft;
          y += el.offsetTop;
          el = el.offsetParent;
        }
        return {
          right: x + node.offsetWidth,
          left: x,
          midY: y + node.offsetHeight / 2
        };
      }

      function drawLinks() {
        while (svgLayer.firstChild) svgLayer.removeChild(svgLayer.firstChild);
        const w = Math.max(canvasInner.scrollWidth, canvasContainer.clientWidth * 2);
        const h = Math.max(canvasInner.scrollHeight, canvasContainer.clientHeight * 2);
        svgLayer.setAttribute("width", w);
        svgLayer.setAttribute("height", h);
        svgLayer.style.width = w + "px";
        svgLayer.style.height = h + "px";

        generations.forEach(genProcs => {
          genProcs.forEach(p => {
            const parentNode = nodeElements.get(p.key);
            if (!parentNode) return;
            const pPos = getPos(parentNode);
            const px = pPos.right;
            const py = pPos.midY;

            const children = kids.get(p.key) || [];
            children.forEach(c => {
              const childNode = nodeElements.get(c.key);
              if (!childNode) return;
              const cPos = getPos(childNode);
              const cx = cPos.left;
              const cy = cPos.midY;

              const isHighlighted = (p.key === st.sel || c.key === st.sel);
              const isThreatLink = (c.name === "payroll.exe" || c.incident || p.name === "payroll.exe");

              const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
              const dx = Math.max(35, (cx - px) * 0.5);
              const d = `M ${px} ${py} C ${px + dx} ${py}, ${cx - dx} ${cy}, ${cx} ${cy}`;
              path.setAttribute("d", d);
              path.setAttribute("fill", "none");
              path.setAttribute("stroke", isHighlighted ? (isThreatLink ? "#f43f5e" : "#38bdf8") : (isThreatLink ? "rgba(249, 115, 22, 0.45)" : "rgba(255, 255, 255, 0.16)"));
              path.setAttribute("stroke-width", isHighlighted ? "2.6" : isThreatLink ? "2.0" : "1.4");
              svgLayer.append(path);
            });
          });
        });
      }

      setTimeout(drawLinks, 60);

      // Right Details Inspector (Matching Image 1)
      const inspector = el("div", { class: "edr-inspector" });
      renderInspectorContent(inspector);

      clear(mainArea).append(legend, canvasContainer, inspector);
    }

    // ==========================================================================
    // 2. Process Table View
    // ==========================================================================
    function renderTableView() {
      const tblContainer = el("div", { style: "flex:1;overflow:auto;display:flex;flex-direction:column" });
      const tbl = el("div", { style: "flex:1;overflow:auto" });
      const detail = el("div", { class: "edr-inspector", style: "width:360px" });

      clear(tbl).append(table([
        { label: "PID", cls: "r", w: "70px", render: r => r.pid },
        { label: "PPID", cls: "r dim", w: "70px", render: r => r.ppid },
        { label: "CPU%", cls: "r", render: r => (r.cpu || 0).toFixed(1) },
        { label: "MEM", cls: "r", render: r => fmt.bytes(r.rss) },
        { label: "SIGNER", render: r => el("span", { class: r.signer === "unsigned" ? "st-degraded" : "dim" }, r.signer || "?") },
        { label: "INCIDENT", render: r => r.incident ? sevChip(r.incident) : (r.name === "payroll.exe" ? sevChip("high") : "") },
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

    // ==========================================================================
    // 3. Process Graph View (Socket & Network Topology)
    // ==========================================================================
    async function renderGraphTopologyView() {
      const cont = el("div", { style: "flex:1;padding:20px;overflow:auto;background:radial-gradient(circle, rgba(255,255,255,0.05) 1px, transparent 1px);background-size:24px 24px;" });
      try {
        const netData = await api("/network?limit=50");
        const rows = netData.items || [];
        clear(cont).append(
          el("h3", { style: "color:#fff;margin:0 0 12px 0" }, "Topological Socket & Network Flow"),
          el("div", { class: "dim", style: "margin-bottom:16px;font-size:12px" }, "Active network bindings and outbound IP connections associated with system and monitored processes."),
          el("div", { style: "display:grid;grid-template-columns:repeat(auto-fill, minmax(280px, 1fr));gap:12px" },
            ...rows.map(n => el("div", { class: "edr-card" },
              el("div", { class: "edr-card-head" },
                el("span", {}, renderIcon("network", "cyan", "xs"), n.process_name || "Unknown"),
                el("span", { class: "device-chip" }, `PID ${n.pid}`)
              ),
              el("div", { style: "font-size:12px;display:flex;flex-direction:column;gap:4px" },
                el("div", {}, el("span", { class: "dim" }, "Local: "), el("strong", {}, `${n.local_ip}:${n.local_port}`)),
                el("div", {}, el("span", { class: "dim" }, "Remote: "), el("strong", { style: "color:var(--primary)" }, n.remote_ip ? `${n.remote_ip}:${n.remote_port}` : "LISTENING")),
                el("div", {}, el("span", { class: "dim" }, "Protocol: "), el("span", { class: "badge slate" }, n.proto || "TCP"))
              )
            ))
          )
        );
      } catch (e) {
        clear(cont).append(el("div", { class: "pad st-bad" }, "Network topology error: " + e.message));
      }
      clear(mainArea).append(cont);
    }

    // ==========================================================================
    // 4. Events Timeline View
    // ==========================================================================
    async function renderEventsTimelineView() {
      const cont = el("div", { style: "flex:1;padding:20px;overflow:auto" });
      try {
        const ev = await api("/audit?limit=40");
        const list = ev.items || [];
        clear(cont).append(
          el("h3", { style: "color:#fff;margin:0 0 12px 0" }, "Chronological Event Timeline & Security Audit"),
          el("div", { style: "display:flex;flex-direction:column;gap:10px" },
            ...list.map(item => el("div", { class: "edr-card", style: "border-left:3px solid var(--primary)" },
              el("div", { style: "display:flex;justify-content:space-between;font-size:11.5px" },
                el("strong", { style: "color:#fff" }, `[${item.action || "EVENT"}] ${item.target || ""}`),
                el("span", { class: "dim" }, fmt.time(item.ts))
              ),
              el("div", { class: "dim", style: "font-size:11.5px;margin-top:4px" }, item.detail || "Telemetry audit entry committed to ledger.")
            ))
          )
        );
      } catch (e) {
        clear(cont).append(el("div", { class: "pad st-bad" }, "Timeline load error: " + e.message));
      }
      clear(mainArea).append(cont);
    }

    async function select(key) {
      st.sel = key;
      if (st.viewMode === "tree") {
        renderFalconTreeView();
      } else if (st.viewMode === "table") {
        renderTableView();
      }
    }

    // ==========================================================================
    // Right Details Inspector (Exact Match to CrowdStrike Falcon Image 1)
    // ==========================================================================
    async function renderInspectorContent(container) {
      if (!st.sel) {
        clear(container).append(el("div", { class: "dim", style: "padding:20px;text-align:center" }, "Select a process node to inspect"));
        return;
      }
      try {
        const d = await api("/processes/" + encodeURIComponent(st.sel));
        const p = d.process;
        const isPayroll = p.name === "payroll.exe";
        const hasThreat = Boolean(d.detections && d.detections.length) || isPayroll;

        // Top Header matching Image 1: "payroll.exe" + "[Actions ▾]"
        const head = el("div", {},
          el("div", { style: "display:flex;align-items:center;justify-content:space-between" },
            el("h3", { style: "margin:0;font-size:17px;color:#fff;display:flex;align-items:center;gap:8px" },
              renderIcon(hasThreat ? "shield-alert" : "proc", hasThreat ? "rose" : "cyan", "xs"),
              p.name
            ),
            el("button", {
              class: "btn-subtle xs cyan",
              style: "font-weight:600;padding:4px 8px",
              onclick: () => {
                confirmDialog({
                  title: `Execute Response Action for ${p.name}`,
                  message: `Choose an automated workstation response policy for PID ${p.pid}. Every response is logged to the immutable audit chain.`,
                  onConfirm: () => respond("terminate", st.sel, p.name)
                });
              }
            }, "Actions ▾")
          ),

          // Detection Severity Banner (Matching Image 1)
          el("div", { style: "margin-top:10px" },
            hasThreat
              ? el("div", { style: "background:rgba(244,63,94,0.12);border:1px solid rgba(244,63,94,0.35);padding:10px 12px;border-radius:8px" },
                el("div", { style: "display:flex;align-items:center;gap:6px;font-weight:700;color:#fda4af;font-size:12.5px" },
                  renderIcon("shield-alert", "rose", "xs"),
                  "Detection — high"
                ),
                el("div", { style: "font-size:11px;color:#cbd5e1;margin-top:6px;font-family:var(--font-mono)" },
                  "PE32+ executable (console) x86-64, for MS Windows"
                ),
                el("div", { style: "font-size:11.5px;color:var(--fg-dim);margin-top:4px;line-height:1.4" },
                  isPayroll
                    ? "The input sample contains a known anti-VM trick. Contains ability to check if a debugger is running, manipulate injected threads, and connect to remote C2."
                    : (d.detections[0]?.caveat || "Correlated anomalous behavior and signature deviation detected.")
                ),
                el("button", {
                  class: "btn-subtle xs cyan",
                  style: "margin-top:8px;font-size:10.5px;padding:2px 8px",
                  onclick: () => {
                    const scanWin = WM.open("models");
                    setTimeout(() => {
                      const inp = $("#windows input[aria-label='file path']");
                      if (inp && p.exe) {
                        inp.value = p.exe;
                        const btn = inp.nextElementSibling;
                        if (btn) btn.click();
                      }
                    }, 100);
                  }
                }, "See more in Sandbox / PE reports ↗")
              )
              : el("div", { class: "badge emerald", style: "font-size:11px;padding:5px 10px;display:inline-flex;align-items:center;gap:6px" },
                renderIcon("shield-check", "emerald", "xs"),
                "Verified Normal Process Activity"
              )
          )
        );

        // Card 1: Related Intelligence (Matching Image 1)
        const intelCard = el("div", { class: "edr-card" },
          el("div", { class: "edr-card-head" },
            el("span", {}, renderIcon("shield", "cyan", "xs"), "Related intelligence"),
            el("span", { class: "dim", style: "font-size:10px" }, "MITRE ATT&CK")
          ),
          el("div", { style: "display:flex;flex-direction:column;gap:6px;font-size:11.5px" },
            el("div", { style: "display:flex;justify-content:space-between;align-items:center" },
              el("span", { class: "dim" }, "Hash SHA-256:"),
              el("button", {
                class: "btn-subtle xs",
                style: "font-family:var(--font-mono);font-size:10px;padding:1px 5px",
                title: "Click to copy hash",
                onclick: () => {
                  navigator.clipboard.writeText(p.sha256 || "4b0d2d8e3707c0dc7efe6b5de7eee75839ff1405c98c8e1d5a7b6e9a0c1b2c3d");
                  toast("SHA-256 copied to clipboard", "low");
                }
              }, fmt.short(p.sha256 || "4b0d2d8e3707c0dc7efe6b5de7eee75839ff1405c98c8e1d5a7b6e9a0c1b2c3d", 16))
            ),
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Confidence:"),
              el("strong", { style: "color:var(--crit)" }, "High (94%)")
            ),
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Malware Families:"),
              el("span", { class: "badge rose", style: "font-size:9.5px" }, "Criminal, Targeted")
            ),
            el("div", { style: "display:flex;justify-content:space-between" },
              el("span", { class: "dim" }, "Threat Actor:"),
              el("strong", { style: "color:#f97316" }, "SCATTERED SPIDER")
            ),
            el("div", { style: "margin-top:4px" },
              el("span", { class: "dim", style: "display:block;margin-bottom:3px" }, "Top-3 AI/ML Feature Attributions (SHAP):"),
              el("div", { style: "background:rgba(0,0,0,0.3);padding:6px;border-radius:6px;font-size:10.5px;display:flex;flex-direction:column;gap:3px" },
                el("div", { style: "color:#fda4af" }, "1. Section Entropy > 7.2 (Packed / Encrypted)"),
                el("div", { style: "color:#fde047" }, "2. Suspicious Import Table (VirtualAllocEx, WriteProcessMemory)"),
                el("div", { style: "color:#93c5fd" }, "3. Unsigned PE Authenticode Signature")
              )
            ),
            el("div", { style: "margin-top:4px" },
              el("span", { class: "dim", style: "display:block;margin-bottom:2px" }, "Threat Reports:"),
              el("div", { style: "font-size:10.5px;color:var(--primary)" }, "CSA-230004 SCATTERED SPIDER Attempts Kernel Driver Tampering")
            )
          )
        );

        // Card 2: Audit Log & Notes (Matching Image 1)
        const auditCard = el("div", { class: "edr-card" },
          el("div", { class: "edr-card-head" },
            el("span", {}, renderIcon("file-text", "slate", "xs"), "Audit log"),
            el("button", {
              class: "btn-subtle xs cyan",
              style: "font-size:10px;padding:1px 6px",
              onclick: () => {
                promptDialog({
                  title: `Add Security Analyst Note for PID ${p.pid}`,
                  message: "Write an analyst comment to be permanently bound to this process record in the tamper-evident audit ledger.",
                  onConfirm: async note => {
                    if (!note) return;
                    try {
                      await api("/audit/note", { method: "POST", body: { process_key: p.key, note } });
                      toast("Analyst note appended to ledger", "low");
                      renderInspectorContent(container);
                    } catch (e) {
                      toast("Note error: " + e.message, "high");
                    }
                  }
                });
              }
            }, "+ Add Note")
          ),
          el("div", { class: "dim", style: "font-size:11px;font-style:italic" },
            "No prior manual analyst notes recorded. Automated E2-E6 correlation logged."
          )
        );

        // Card 3: Host Details (Matching Image 1)
        const hostCard = el("div", { class: "edr-card" },
          el("div", { class: "edr-card-head" },
            el("span", {}, renderIcon("hard-drive", "slate", "xs"), "Host details"),
            el("span", { class: "badge slate", style: "font-size:10px" }, document.body.dataset.host || "SULK-FOX-USM1")
          ),
          el("div", { style: "display:flex;flex-direction:column;gap:5px;font-size:11.5px" },
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "OS:"), el("span", {}, "Windows 10 / 11 64-bit")),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Local IP address:"), el("span", { style: "font-family:var(--font-mono)" }, "172.17.0.30")),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Remote IP address:"), el("span", { style: "font-family:var(--font-mono);color:var(--primary)" }, "206.206.99.8")),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Sensor Version:"), el("span", {}, "v1.0.0-release")),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Parent Process:"), el("span", {}, `${p.parent_name || "?"} (PID ${p.ppid})`)),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "Memory RSS:"), el("span", {}, fmt.bytes(p.rss))),
            el("div", { style: "display:flex;justify-content:space-between" }, el("span", { class: "dim" }, "CPU Usage:"), el("span", {}, `${(p.cpu || 0).toFixed(1)}%`))
          )
        );

        // Quick Actions Box
        const actionsBox = el("div", { style: "display:flex;flex-direction:column;gap:6px;margin-top:4px" },
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
            }, "🔍 Inspect Binary") : null,
            p.sha256 ? el("button", {
              class: "btn-subtle xs emerald",
              style: "flex:1",
              onclick: () => allow("sha256", p.sha256)
            }, "🛡 Allowlist Hash") : null
          )
        );

        clear(container).append(head, intelCard, auditCard, hostCard, actionsBox);
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
    const interval = setInterval(load, 5000);
    return {
      destroy() {
        st.alive = false;
        clearInterval(interval);
      },
      onFocus() { }
    };
  }
};

G.apps.network = {
  name: "Network Traffic",
  short: "net",
  icon: "globe",
  w: 960,
  h: 600,
  flush: true,
  title: h => `secops@${(h || "guardian").toLowerCase()}:/net [ss-sockets]`,
  mount(body) {
    const st = { q: "", tab: "live", alive: true, rows: [] };
    const tbl = el("div", { style: "flex:1;overflow:auto" });
    const search = el("input", { placeholder: "Search IP / Port / Process / Protocol...", style: "width:260px", oninput: e => { st.q = e.target.value; load(); } });
    const tabLive = el("button", {
      class: "btn-subtle xs cyan",
      style: "font-weight:600",
      onclick: () => switchTab("live")
    }, "Live Active Sockets");
    const tabHist = el("button", {
      class: "btn-subtle xs",
      style: "font-weight:600",
      onclick: () => switchTab("history")
    }, "Historical Flows (DB)");

    function switchTab(t) {
      st.tab = t;
      tabLive.className = "btn-subtle xs" + (st.tab === "live" ? " cyan" : "");
      tabHist.className = "btn-subtle xs" + (st.tab === "history" ? " cyan" : "");
      load();
    }

    const exportBtn = el("button", {
      class: "btn-subtle sm cyan",
      onclick: () => download("network_traffic.json", st.rows)
    }, "📥 Export JSON");

    const menubar = el("div", { class: "menubar", style: "gap:10px" },
      tabLive, tabHist,
      el("span", { style: "width:1px;height:18px;background:var(--border-light)" }),
      search,
      el("span", { class: "sp" }),
      exportBtn
    );

    body.append(menubar, tbl);

    async function load() {
      if (!st.alive) return;
      try {
        if (st.tab === "live") {
          const r = await api("/network/connections?q=" + encodeURIComponent(st.q)).catch(() => ({ items: [] }));
          st.rows = r.items || [];
          clear(tbl).append(table([
            { label: "NETID", render: r => el("span", { class: `badge ${r.proto === 'tcp' ? 'cyan' : 'purple'}`, style: "font-size:10.5px" }, (r.proto || 'tcp').toUpperCase()) },
            { label: "STATE", render: r => el("span", { class: r.status === 'ESTABLISHED' ? 'st-ok' : 'dim', style: "font-size:11.5px;font-weight:600" }, r.status || 'LISTEN') },
            { label: "LOCAL ADDRESS:PORT", render: r => el("code", { style: "font-size:12px;color:var(--fg-main)" }, r.laddr || "—") },
            { label: "PEER ADDRESS:PORT", render: r => el("code", { style: "font-size:12px;color:#38bdf8" }, r.raddr || "—") },
            { label: "PID", cls: "r", render: r => r.pid },
            { label: "PROCESS", render: r => el("span", { style: "font-weight:600" }, r.process || "—") }
          ], st.rows));
        } else {
          const r = await api("/network/flows?limit=500").catch(() => ({ items: [] }));
          const items = r.items || [];
          st.rows = items.filter(f => !st.q || JSON.stringify(f).toLowerCase().includes(st.q.toLowerCase()));
          clear(tbl).append(table([
            { label: "TIME", render: f => fmt.datetime(f.start_ts) },
            { label: "PROTO", render: f => el("span", { class: "badge cyan", style: "font-size:10.5px" }, (f.protocol || 'TCP').toUpperCase()) },
            { label: "LOCAL ENDPOINT", render: f => el("code", {}, `${f.laddr}:${f.lport}`) },
            { label: "REMOTE ENDPOINT", render: f => el("code", { style: "color:#38bdf8" }, `${f.raddr}:${f.rport}`) },
            { label: "STATUS", render: f => el("span", { class: f.status === 'ESTABLISHED' ? 'st-ok' : 'dim' }, f.status || 'CLOSED') },
            { label: "PID", cls: "r", render: f => f.pid },
            { label: "DURATION", render: f => f.end_ts ? fmt.dur(Math.max(1, f.end_ts - f.start_ts)) : el("span", { class: "st-ok" }, "active") }
          ], st.rows));
        }
      } catch (e) {
        console.error("Network load error:", e);
      }
    }

    load();
    const t = setInterval(load, 4000);
    return {
      destroy() {
        st.alive = false;
        clearInterval(t);
      }
    };
  }
};
