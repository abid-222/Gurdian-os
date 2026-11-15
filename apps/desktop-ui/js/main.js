"use strict";
(function () {
  const DOCK = ["home", "terminal", "processes", "network", "security", "system", "timeline", "models", "settings"];
  const DOCK_LABELS = {
    home: "Overview",
    terminal: "Terminal Shell",
    processes: "Process Tree",
    network: "Network Traffic",
    security: "Security & Alerts",
    system: "System Health",
    timeline: "Event Timeline",
    models: "File Scanner",
    settings: "Settings"
  };

  /* token: arrives in the URL fragment (never sent to the server), moved to storage, fragment removed */
  const m = /[#&]t=([\w-]+)/.exec(location.hash);
  if (m) {
    try {
      sessionStorage.setItem("g_tok", m[1]);
      localStorage.setItem("g_tok", m[1]);
    } catch (e) {}
    history.replaceState(null, "", location.pathname);
  }
  G.token = sessionStorage.getItem("g_tok") || localStorage.getItem("g_tok");

  const theme = localStorage.getItem("g_theme");
  if (theme) document.documentElement.dataset.theme = theme;
  const themeBtn = $("#themeBtn");
  if (themeBtn) {
    themeBtn.onclick = () => {
      const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = t;
      try { localStorage.setItem("g_theme", t); } catch (e) {}
    };
  }

  async function init() {
    try {
      if (!G.token) {
        const sRes = await fetch("/api/v1/auth/session");
        if (sRes.ok) {
          const sData = await sRes.json();
          if (sData.token) {
            G.token = sData.token;
            try {
              sessionStorage.setItem("g_tok", G.token);
              localStorage.setItem("g_tok", G.token);
            } catch (e) {}
          }
        }
      }
      const h = await api("/health");
      document.body.dataset.host = h.hostname;
      start(h);
    } catch (err) {
      console.error("Failed to start Guardian UI:", err);
      setTimeout(async () => {
        try {
          const sRes = await fetch("/api/v1/auth/session");
          if (sRes.ok) {
            const sData = await sRes.json();
            G.token = sData.token;
          }
          const h = await api("/health");
          document.body.dataset.host = h.hostname;
          start(h);
        } catch (e2) {}
      }, 500);
    }
  }

  function start(h) {
    const userEl = $("#tUser");
    if (userEl) userEl.textContent = `guardian@${h.hostname.toLowerCase()}`;

    const dock = $("#dock");
    if (dock) {
      clear(dock);
      DOCK.forEach(id => {
        const a = G.apps[id];
        if (!a) return;
        const btn = el("button", {
          dataset: { app: id, tooltip: DOCK_LABELS[id] || a.name },
          title: `${DOCK_LABELS[id] || a.name} (Alt+${DOCK.indexOf(id) + 1})`,
          "aria-label": DOCK_LABELS[id] || a.name,
          onclick: () => WM.toggle(id)
        },
          renderIcon(WM.alias(a.icon), "slate", "md"),
          id === "security" ? el("span", { class: "badge" }) : null
        );
        dock.append(btn);
      });
    }

    // Open Home & Terminal initially
    WM.open("home", { x: 36, y: 18, w: 980, h: 680 });
    WM.open("terminal", { x: 120, y: 120, w: 760, h: 420 });
    WM.focus("home");

    connectWS();
    on("health", refresh);
    on("events", () => { });
    refresh();
    setInterval(refresh, 3000);
    setInterval(clock, 1000);
    clock();
    addEventListener("keydown", keys);
  }

  function clock() {
    const d = new Date();
    const clk = $("#clock");
    if (clk) {
      clk.textContent = d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" }) +
        "  " + d.toLocaleTimeString([], { hour12: false });
    }
  }

  async function refresh() {
    try {
      const [h, s] = await Promise.all([api("/health"), api("/system/summary")]);
      G.state.health = h;
      G.state.summary = s;
      const m = s.latest || {};

      const tCpu = $("#tCpu");
      if (tCpu) tCpu.textContent = `CPU ${m.cpu !== null && m.cpu !== undefined ? Math.round(m.cpu) : "--"}%`;

      const tMem = $("#tMem");
      if (tMem) tMem.textContent = `RAM ${m.mem !== null && m.mem !== undefined ? Math.round(m.mem) : "--"}%`;

      const okN = Object.values(h.sources).filter(x => x.status === "available").length;
      const tot = Object.keys(h.sources).length;
      const tSrc = $("#tSrc");
      if (tSrc) {
        tSrc.textContent = `${okN}/${tot} Shields`;
        tSrc.className = okN === tot ? "st-ok" : "st-degraded";
      }

      // Friendly Status Banner Pill (Crisp SVG - No Text Emojis)
      const ban = $("#banner");
      if (ban) {
        clear(ban);
        const crit = s.incidents_open || 0;
        if (h.db.recovery_notice) {
          ban.append(el("span", { class: "bn-pill crit", title: h.db.recovery_notice }, renderIcon("database", "rose", "xs"), el("span", { style: "margin-left:5px" }, "Database Recovered")));
        } else if (h.paused) {
          ban.append(el("span", { class: "bn-pill warn" }, renderIcon("pause", "amber", "xs"), el("span", { style: "margin-left:5px" }, "Monitoring Paused")));
        } else if (h.db.read_only) {
          ban.append(el("span", { class: "bn-pill crit" }, renderIcon("lock", "rose", "xs"), el("span", { style: "margin-left:5px" }, "Database Read-Only")));
        } else if (crit > 0) {
          ban.append(el("span", { class: "bn-pill crit" }, renderIcon("shield-alert", "rose", "xs"), el("span", { style: "margin-left:5px" }, `${crit} Active Incident${crit > 1 ? "s" : ""}`)));
        } else if (!h.admin) {
          ban.append(el("span", { class: "bn-pill warn" }, renderIcon("alert-triangle", "amber", "xs"), el("span", { style: "margin-left:5px" }, "Limited Protection • Needs Admin Access")));
        } else if (h.degraded && h.degraded.length) {
          ban.append(el("span", { class: "bn-pill warn" }, renderIcon("alert-circle", "amber", "xs"), el("span", { style: "margin-left:5px" }, `Degraded: ${h.degraded.join(", ")}`)));
        } else {
          ban.append(el("span", { class: "bn-pill" }, renderIcon("shield-check", "emerald", "xs"), el("span", { style: "margin-left:5px" }, "System Fully Protected")));
        }
      }

      // Update security badge on dock
      const secBadge = $("#dock [data-app=security] .badge");
      if (secBadge) {
        secBadge.textContent = s.incidents_open || "";
      }

      // Compatibility for older status references if present
      const R = $("#tmuxR");
      if (R) {
        clear(R);
        const crit = s.incidents_open;
        R.append(
          el("span", { class: crit ? "bad" : "" }, `inc:${crit}`),
          ` | q:${h.queue.fill_pct}% drop:${h.queue.dropped} | rules:E2-E6 | `,
          el("span", { class: h.status === "ok" ? "" : "warn" }, h.status)
        );
      }
    } catch (e) { }
  }

  /* Command Palette (Spotlight / Linear style) */
  const pal = { items: [], idx: 0 };
  function palItems(q) {
    const apps = DOCK.map(id => ({
      label: "Open " + (DOCK_LABELS[id] || G.apps[id].name),
      hint: "Application",
      run: () => WM.open(id)
    }));
    const cmds = ["status", "sources", "system", "processes --top 20", "pstree", "threads", "alerts --recent", "timeline --hours 2", "models", "privacy", "help"].map(c => ({
      label: "$ " + c,
      hint: "Shell Command",
      run: () => {
        const r = WM.open("terminal");
        setTimeout(() => r.inst.run && r.inst.run(c), 60);
      }
    }));
    const misc = [
      { label: "Tile All Windows", hint: "Window Manager", run: () => WM.tile() },
      { label: "Toggle Dark / Light Theme", hint: "Appearance", run: () => $("#themeBtn").click() }
    ];
    let all = [...apps, ...cmds, ...misc];
    q = q.toLowerCase();
    if (q) {
      all = all.filter(i => q.split(" ").every(w => i.label.toLowerCase().includes(w)));
      if (!all.length || q.split(" ")[0] === "scan") {
        all.push({
          label: "$ " + q,
          hint: "Run in terminal",
          run: () => {
            const r = WM.open("terminal");
            setTimeout(() => r.inst.run && r.inst.run(q), 60);
          }
        });
      }
    }
    return all;
  }

  function palRender() {
    const ul = clear($("#palList"));
    pal.items.forEach((it, i) =>
      ul.append(el("li", {
        class: i === pal.idx ? "on" : "",
        onclick: () => { pal.idx = i; palRun(); }
      },
        it.label,
        el("span", { class: "k" }, it.hint)
      ))
    );
  }

  function palOpen() {
    $("#palette").hidden = false;
    $("#palIn").value = "";
    pal.items = palItems("");
    pal.idx = 0;
    palRender();
    $("#palIn").focus();
  }

  function palClose() {
    $("#palette").hidden = true;
    try { $("#palIn").blur(); } catch (_) {}
  }
  function palRun() { const it = pal.items[pal.idx]; palClose(); it && it.run(); }

  $("#palIn").addEventListener("input", e => { pal.items = palItems(e.target.value); pal.idx = 0; palRender(); });
  $("#palIn").addEventListener("keydown", e => {
    if (e.key === "ArrowDown") { pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); palRender(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { pal.idx = Math.max(0, pal.idx - 1); palRender(); e.preventDefault(); }
    else if (e.key === "Enter") palRun();
    else if (e.key === "Escape" || e.code === "Escape") { e.preventDefault(); e.stopPropagation(); palClose(); }
  });
  $("#palette").addEventListener("mousedown", e => {
    if (e.target.id === "palette" || !e.target.closest(".pal-box")) palClose();
  });
  $("#menuBtn").onclick = palOpen;

  const palKbd = $(".pal-kbd");
  if (palKbd) {
    palKbd.setAttribute("role", "button");
    palKbd.setAttribute("tabindex", "0");
    palKbd.setAttribute("title", "Close palette (Esc)");
    palKbd.onclick = e => {
      e.preventDefault();
      e.stopPropagation();
      palClose();
    };
  }
  const palCloseBtn = $("#palCloseBtn");
  if (palCloseBtn) {
    palCloseBtn.onclick = e => {
      e.preventDefault();
      e.stopPropagation();
      palClose();
    };
  }

  // Universal Escape handler:
  // 1. Closes Command Palette if open
  // 2. Clears focused search input if text is present
  // 3. Closes top active desktop window (WM.close) if any window is open
  function handleEscape(e) {
    const palEl = $("#palette");
    if (palEl && !palEl.hidden) {
      if (e) { e.preventDefault(); e.stopPropagation(); }
      palClose();
      return true;
    }

    const active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA")) {
      if (active.value && active.value.length > 0) {
        active.value = "";
        active.dispatchEvent(new Event("input", { bubbles: true }));
        if (e) { e.preventDefault(); e.stopPropagation(); }
        return true;
      }
    }

    if (window.WM && Array.isArray(WM.order) && WM.order.length > 0) {
      const topId = WM.order[WM.order.length - 1];
      if (topId && WM.wins && WM.wins.has(topId)) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        WM.close(topId);
        return true;
      }
    }
    return false;
  }

  // Global capture for Escape key
  window.addEventListener("keydown", e => {
    if (e.key === "Escape" || e.code === "Escape" || e.keyCode === 27) {
      handleEscape(e);
    }
  }, true);

  function keys(e) {
    if (e.key === "Escape" || e.code === "Escape" || e.keyCode === 27) {
      if (handleEscape(e)) return;
    }
    if ((e.ctrlKey && e.key.toLowerCase() === "k") || (e.altKey && e.code === "Space")) {
      e.preventDefault();
      $("#palette").hidden ? palOpen() : palClose();
    } else if (e.altKey && e.key >= "1" && e.key <= "9") {
      e.preventDefault();
      WM.byIndex(+e.key);
    } else if (e.altKey && e.key.toLowerCase() === "t") {
      e.preventDefault();
      WM.tile();
    } else if (e.altKey && e.key.toLowerCase() === "w") {
      e.preventDefault();
      const id = WM.order[WM.order.length - 1];
      id && WM.close(id);
    }
  }

  init();
})();
