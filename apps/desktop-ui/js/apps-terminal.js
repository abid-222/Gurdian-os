"use strict";
const TERM_CMDS = ["help", "status", "sources", "system", "processes", "alerts", "timeline", "scan", "models", "privacy", "version", "neofetch", "clear", "exit", "pstree", "threads", "sleep", "echo", "cat", "ls", "grep", "head", "tail", "wc", "sort", "jobs", "fg", "bg", "kill"];

G.apps.terminal = {
  name: "Guardian Shell", short: "term", icon: "term", w: 820, h: 500, flush: true, title: h => `Guardian OS — Terminal Shell (${h})`,
  mount(body, rec) {
    const hostname = document.body.dataset.host || "host";
    const out = el("div", { class: "term", tabindex: "-1" });
    body.append(out);
    const hist = JSON.parse(sessionStorage.getItem("g_hist") || "[]"); let hi = hist.length;
    const ps1 = () => el("span", { class: "ps1" }, "guardian", "@", hostname.toLowerCase(), el("u", {}, ":~"), "$ ");
    const print = (t, cls) => out.insertBefore(el("div", { class: cls || "" }, t), input.parentNode);
    const input = el("input", { spellcheck: "false", autocomplete: "off", "aria-label": "terminal input", autocapitalize: "off" });
    const line = el("div", { class: "line" }, ps1(), input); out.append(line);
    out.addEventListener("click", () => { if (!getSelection().toString()) input.focus(); });

    async function neofetch() {
      const h = await api("/health"); const m = (await api("/system/summary")).latest || {};
      const info = [`${"guardian@" + h.hostname.toLowerCase()}`, "-".repeat(10 + h.hostname.length), `OS      ${h.os} ${h.architecture}`, `Build   ${h.os_build}`, `Agent   ${h.status} · v${h.version}`,
        `Uptime  ${fmt.dur(h.uptime_s)}`, `CPU     ${fmt.pct(m.cpu)}   MEM ${fmt.pct(m.mem)}   DISK ${fmt.pct(m.disk)}`, `Threads ${Array.isArray(h.threads) ? h.threads.filter(t => t.alive).length : (h.threads || 0)} active · Queue ${h.queue.depth} events (${h.queue.fill_pct}%)`, `Policy  v${h.policy_version}`,
        `Sensors ${Object.values(h.sources).filter(s => s.status === "available").length}/${Object.keys(h.sources).length} available`];
      const logo = LOGO.split("\n"); const rows = Math.max(logo.length, info.length);
      let txt = ""; for (let i = 0; i < rows; i++) txt += (logo[i] || "").padEnd(34) + (info[i] || "") + "\n";
      print(el("pre", { class: "logo", style: "margin:0" }, txt));
    }
    async function run(cmd) {
      const c = cmd.trim(); if (!c) return;
      hist.push(c); hi = hist.length; sessionStorage.setItem("g_hist", JSON.stringify(hist.slice(-100)));
      print(el("span", {}, ps1(), c));
      const w = c.split(/\s+/)[0].toLowerCase();
      if (w === "clear") { [...out.children].forEach(n => n !== line && n.remove()); return; }
      if (w === "exit") return WM.close("terminal");
      if (w === "neofetch") return neofetch();
      try { const r = await api("/terminal", { method: "POST", body: { line: c } }); print(r.output, r.ok ? "" : "err"); }
      catch (e) { print(e.message, "err"); }
      out.scrollTop = out.scrollHeight;
    }
    input.addEventListener("keydown", e => {
      if (e.key === "Enter") { const v = input.value; input.value = ""; run(v); }
      else if (e.key === "ArrowUp") { if (hi > 0) input.value = hist[--hi]; e.preventDefault(); }
      else if (e.key === "ArrowDown") { input.value = hi < hist.length - 1 ? hist[++hi] : ""; hi = Math.min(hi, hist.length); e.preventDefault(); }
      else if (e.key === "Tab") { e.preventDefault(); const m = TERM_CMDS.filter(x => x.startsWith(input.value.toLowerCase())); if (m.length === 1) input.value = m[0] + " "; else if (m.length > 1) print(m.join("  "), "hint"); }
      else if (e.ctrlKey && e.key.toLowerCase() === "l") { e.preventDefault(); run("clear"); }
    });
    print(`Smart OS Guardian ${"0.3.0"} — Guardian Shell. Type 'help'. Arbitrary shell execution is disabled by design.`, "hint");
    neofetch();
    return { onFocus() { input.focus(); }, run };
  },
};
