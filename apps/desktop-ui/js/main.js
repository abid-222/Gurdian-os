"use strict";
(function () {
  const DOCK = ["home", "terminal", "processes", "network", "security", "system", "timeline", "models", "settings"];

  /* token: arrives in the URL fragment (never sent to the server), moved to sessionStorage, fragment removed */
  const m = /[#&]t=([\w-]+)/.exec(location.hash);
  if (m) { sessionStorage.setItem("g_tok", m[1]); history.replaceState(null, "", location.pathname); }
  G.token = sessionStorage.getItem("g_tok");
  const theme = localStorage.getItem("g_theme"); if (theme) document.documentElement.dataset.theme = theme;
  $("#themeBtn").onclick = () => { const t = document.documentElement.dataset.theme === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = t; try { localStorage.setItem("g_theme", t); } catch (e) { } };
  $("#tokenBtn").onclick = () => { G.token = $("#tokenIn").value.trim(); sessionStorage.setItem("g_tok", G.token); location.reload(); };

  const sleep = ms => new Promise(r => setTimeout(r, ms));
  async function boot() {
    const b = $("#boot"); let skip = false; b.onclick = () => skip = true;
    const line = async (tag, msg, cls = "ok", d = 55) => { b.append(el("div", {}, el("span", { class: cls }, `[ ${tag} ] `), msg)); if (!skip) await sleep(d); };
    b.append(el("div", { class: "dim" }, "Smart OS Guardian — boot (click to skip)\n"));
    if (!G.token) { b.remove(); return showLock(); }
    let h;
    try { h = await api("/health"); } catch (e) { await line(" FAIL ", "agent unreachable: " + e.message, "fail"); return; }
    document.body.dataset.host = h.hostname;
    await line("  OK  ", `Reached guardiand on 127.0.0.1 (loopback only, token authenticated)`);
    await line("  OK  ", `Mounted local store  ${h.db.path.split(/[\\/]/).slice(-2).join("/")}  (SQLite, WAL)`);
    await line(h.db.audit_chain_ok ? "  OK  " : "FAILED", "Verified audit hash chain", h.db.audit_chain_ok ? "ok" : "fail");
    for (const [k, v] of Object.entries(h.sources)) {
      const t = v.status === "available" ? "  OK  " : v.status === "degraded" ? " WARN " : " SKIP ";
      await line(t, `${v.status === "available" ? "Started" : v.status === "degraded" ? "Degraded:" : "Unavailable:"} ${k}${v.reason && v.status !== "available" ? "  — " + fmt.short(v.reason, 70) : ""}`, v.status === "available" ? "ok" : v.status === "degraded" ? "warn" : "dim", 35);
    }
    await line(h.model.loaded ? "  OK  " : " WARN ", h.model.loaded ? `Loaded PE model ${h.model.version}` : "No PE model installed — running rules-only", h.model.loaded ? "ok" : "warn");
    await line("  OK  ", `Loaded correlation policy v${h.policy_version}`);
    await line("  OK  ", "Reached target Guardian Workstation.", "ok", 250);
    b.remove(); start(h);
  }

  function start(h) {
    $("#shell").hidden = false; $("#tUser").textContent = `guardian@${h.hostname.toLowerCase()}`;
    const dock = $("#dock");
    DOCK.forEach(id => { const a = G.apps[id]; dock.append(el("button", { dataset: { app: id }, title: `${a.name}  (Alt+${DOCK.indexOf(id) + 1})`, "aria-label": a.name, onclick: () => WM.toggle(id) }, WM.svg(a.icon), id === "security" ? el("span", { class: "badge" }) : null)); });
    WM.open("home", { x: 30, y: 18, w: 880, h: 560 }); WM.open("terminal", { x: 120, y: 130, w: 700, h: 360 }); WM.focus("terminal");
    connectWS(); on("health", refresh); on("events", () => { }); refresh(); setInterval(refresh, 3000); setInterval(clock, 1000); clock();
    addEventListener("keydown", keys);
  }

  function clock() { const d = new Date(); $("#clock").textContent = d.toLocaleDateString([], { weekday: "short", month: "short", day: "numeric" }) + "  " + d.toLocaleTimeString([], { hour12: false }); }

  async function refresh() {
    try {
      const [h, s] = await Promise.all([api("/health"), api("/system/summary")]); G.state.health = h; G.state.summary = s; const m = s.latest || {};
      $("#tCpu").textContent = "cpu " + (m.cpu ?? "--") + "%"; $("#tMem").textContent = "mem " + (m.mem ?? "--") + "%";
      const okN = Object.values(h.sources).filter(x => x.status === "available").length, tot = Object.keys(h.sources).length;
      $("#tSrc").textContent = `src ${okN}/${tot}`; $("#tSrc").className = okN === tot ? "st-ok" : "st-degraded";
      const ban = $("#banner"); clear(ban);
      const crit = s.incidents_open;
      if (h.db.recovery_notice) ban.append(el("span", { class: "bn crit", title: h.db.recovery_notice }, "⚠ database was recovered - see Home"));
      else if (h.paused) ban.append(el("span", { class: "bn" }, "⏸ collection paused"));
      else if (h.db.read_only) ban.append(el("span", { class: "bn crit" }, "✖ database read-only: " + (h.db.error || "")));
      else if (h.degraded.length) ban.append(el("span", { class: "bn", title: h.degraded.map(k => k + ": " + h.sources[k].reason).join("\n") }, "⚠ degraded sensors: " + h.degraded.join(", ")));
      else if (h.queue.state !== "ok") ban.append(el("span", { class: "bn" }, `⚠ event queue ${h.queue.state} (${h.queue.fill_pct}%) — dropped ${h.queue.dropped}`));
      const R = $("#tmuxR"); clear(R);
      R.append(el("span", { class: crit ? "bad" : "" }, `inc:${crit}`), ` | q:${h.queue.fill_pct}% drop:${h.queue.dropped} | `, h.model.loaded ? "model:on" : "model:none", " | ", el("span", { class: h.status === "ok" ? "" : "warn" }, h.status), " | ", new Date().toLocaleTimeString([], { hour12: false }));
      const c = $("#conky"); const hist = (await api("/system/history")).samples, last = hist[hist.length - 1] || {};
      const bar_ = p => "█".repeat(Math.round((p || 0) / 10)).padEnd(10, "░");
      c.textContent = ""; c.append(el("b", {}, `${h.hostname}`), `\n${h.os} · ${h.architecture}\nuptime ${fmt.dur(last.uptime || h.uptime_s)}\n`, el("b", {}, "CPU "), `${bar_(last.cpu)} ${(last.cpu || 0).toFixed(0)}%\n`, el("b", {}, "RAM "), `${bar_(last.mem)} ${(last.mem || 0).toFixed(0)}%\n`, el("b", {}, "DSK "), `${bar_(last.disk)} ${(last.disk || 0).toFixed(0)}%\n`, el("b", {}, "NET "), `${s.connection_count} conns · ${s.process_count} procs`);
    } catch (e) { }
  }

  /* command palette (rofi-style): apps + guardian commands */
  const pal = { items: [], idx: 0 };
  function palItems(q) {
    const apps = DOCK.map(id => ({ label: "open " + G.apps[id].name, hint: "app", run: () => WM.open(id) }));
    const cmds = ["status", "sources", "system", "processes --top 20", "alerts --recent", "timeline --hours 2", "models", "privacy", "help"].map(c => ({ label: "$ " + c, hint: "guardian", run: () => { const r = WM.open("terminal"); setTimeout(() => r.inst.run && r.inst.run(c), 60); } }));
    const misc = [{ label: "tile windows", hint: "wm", run: () => WM.tile() }, { label: "toggle light/dark theme", hint: "ui", run: () => $("#themeBtn").click() }];
    let all = [...apps, ...cmds, ...misc]; q = q.toLowerCase();
    if (q) { all = all.filter(i => q.split(" ").every(w => i.label.toLowerCase().includes(w))); if (!all.length || q.split(" ")[0] === "scan") all.push({ label: "$ " + q, hint: "run in terminal", run: () => { const r = WM.open("terminal"); setTimeout(() => r.inst.run && r.inst.run(q), 60); } }); }
    return all;
  }
  function palRender() { const ul = clear($("#palList")); pal.items.forEach((it, i) => ul.append(el("li", { class: i === pal.idx ? "on" : "", onclick: () => { pal.idx = i; palRun(); } }, it.label, el("span", { class: "k" }, it.hint)))); }
  function palOpen() { $("#palette").hidden = false; $("#palIn").value = ""; pal.items = palItems(""); pal.idx = 0; palRender(); $("#palIn").focus(); }
  function palClose() { $("#palette").hidden = true; }
  function palRun() { const it = pal.items[pal.idx]; palClose(); it && it.run(); }
  $("#palIn").addEventListener("input", e => { pal.items = palItems(e.target.value); pal.idx = 0; palRender(); });
  $("#palIn").addEventListener("keydown", e => {
    if (e.key === "ArrowDown") { pal.idx = Math.min(pal.items.length - 1, pal.idx + 1); palRender(); e.preventDefault(); }
    else if (e.key === "ArrowUp") { pal.idx = Math.max(0, pal.idx - 1); palRender(); e.preventDefault(); }
    else if (e.key === "Enter") palRun(); else if (e.key === "Escape") palClose();
  });
  $("#palette").addEventListener("mousedown", e => { if (e.target.id === "palette") palClose(); });
  $("#menuBtn").onclick = palOpen;

  function keys(e) {
    if ((e.ctrlKey && e.key.toLowerCase() === "k") || (e.altKey && e.code === "Space")) { e.preventDefault(); $("#palette").hidden ? palOpen() : palClose(); }
    else if (e.altKey && e.key >= "1" && e.key <= "9") { e.preventDefault(); WM.byIndex(+e.key); }
    else if (e.altKey && e.key.toLowerCase() === "t") { e.preventDefault(); WM.tile(); }
    else if (e.altKey && e.key.toLowerCase() === "w") { e.preventDefault(); const id = WM.order[WM.order.length - 1]; id && WM.close(id); }
  }
  boot();
})();
