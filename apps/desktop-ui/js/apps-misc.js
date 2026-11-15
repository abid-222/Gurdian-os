"use strict";

G.apps.models = {
  name: "File Scanner", short: "scan", icon: "model", w: 860, h: 600, title: h => `Guardian OS — File Scanner (${h})`,
  mount(body) {
    let alive = true;
    const render = async () => {
      const m = await api("/models");
      const a = m.active;
      const out = el("div", { class: "scanout", style: "margin-top:8px" });
      const pathIn = el("input", { placeholder: "Full path of executable or file to inspect (e.g. C:\\Windows\\explorer.exe)", style: "width:75%", "aria-label": "file path" });

      const scan = async () => {
        const p = pathIn.value.trim().replace(/^"|"$/g, ""); if (!p) return;
        clear(out).append(el("div", { class: "dim" }, "scanning file statically..."));
        try {
          const r = await api("/scan", { method: "POST", body: { path: p } }), f = r.file;
          if (!f.exists) { clear(out).append(el("div", { class: "note" }, "not a file: " + p)); return; }
          const rows = [
            ["file", f.path],
            ["sha256", f.sha256],
            ["size", fmt.bytes(f.size)],
            ["PE format", f.is_pe ? "valid PE header (MZ)" : "not a PE file"],
            ["signer", f.signer || "n/a"],
            ["origin (Mark of the Web)", f.origin ? `${f.origin.zone || "?"}${f.origin.origin_host ? " - " + f.origin.origin_host : ""}` : "none / local file"],
            ["imports", (f.imports || []).slice(0, 12).join(", ") || "none"],
            ["high-entropy sections", (f.high_entropy_sections || []).join(", ") || "none"],
            ["W+X sections", (f.wx_sections || []).join(", ") || "none"],
            ["E1 model score", r.model ? `score ${r.model.score} (threshold ${r.model.threshold}, inference ${r.model.inference_time_ms} ms)` : "Not installed (optional) — running rules E2–E6"],
            ["execution safety", "never executed (static OS inspection only)"]
          ];
          clear(out).append(
            kv(rows),
            f.sections && f.sections.length ? el("div", { style: "margin-top:8px" },
              el("div", { style: "font-weight:600;margin-bottom:3px;color:var(--accent)" }, "PE Header Sections:"),
              table([
                { k: "name", label: "SECTION" },
                { label: "VSIZE", cls: "r", render: s => fmt.bytes(s.vsize) },
                { label: "RSIZE", cls: "r", render: s => fmt.bytes(s.rsize) },
                { label: "ENTROPY", cls: "r", render: s => (s.entropy || 0).toFixed(2) },
                { label: "FLAGS", render: s => (s.exec ? "EXEC " : "") + (s.write ? "WRITE" : "") }
              ], f.sections)
            ) : null,
            r.warning ? el("div", { class: "note" }, r.warning) : null
          );
        } catch (e) { clear(out).append(el("div", { class: "note" }, e.message)); }
      };

      pathIn.addEventListener("keydown", e => { if (e.key === "Enter") scan(); });

      clear(body).append(el("div", { class: "pad" },
        el("div", { class: "card" },
          el("h4", {}, "File Intelligence & Static Inspection"),
          el("div", { class: "dim", style: "margin-bottom:8px" }, "Files are strictly read and parsed statically — never executed. Extracts SHA-256 hash, PE header sections, Shannon entropy, imports table, Authenticode signer, and NTFS Mark-of-the-Web Zone.Identifier stream."),
          el("div", { style: "display:flex;gap:6px" }, pathIn, el("button", { onclick: scan }, "Scan File")),
          out
        ),
        el("h3", { style: "margin-top:14px" }, "E1 Machine Learning Slot"),
        a ? kv([["model", a.model_id], ["version", a.version], ["status", m.validated ? "validated - counts as E1 evidence" : "NOT validated - scores shown, never counted as evidence"], ["feature schema", a.feature_schema_version], ["sha256", fmt.short(a.hash, 32)],
                ["high threshold", a.threshold_high], ["calibrated", a.calibrated ? "yes" : "no"], ["trained on", a.trained_on || "—"]])
          : el("div", { class: "note" }, "Not installed (optional) — running rules E2–E6"),
        m.warning ? el("div", { class: "note" }, m.warning) : null,
        el("h3", { style: "margin-top:14px" }, "Feature Extractor"),
        kv([["schema", m.extractor_schema], ["status", m.extractor.available ? "ready" : "Not installed (optional) — " + fmt.short(m.extractor.reason, 120)]]),
        el("div", { class: "dim", style: "margin-top:10px" }, m.note)
      ));
    };
    render().catch(e => body.append(el("div", { class: "pad st-bad" }, e.message)));
    return { destroy() { alive = false; } };
  },
};

G.apps.settings = {
  name: "Settings & Privacy", short: "cfg", icon: "cfg", w: 860, h: 640, title: h => `Guardian OS — Settings & Privacy (${h})`,
  mount(body) {
    let alive = true;
    async function draw() {
      const [p, al, au, h, qr] = await Promise.all([api("/settings/privacy"), api("/allowlist"), api("/audit?limit=30"), api("/health"), api("/quarantine")]);
      const tog = (k, label, note) => el("label", { style: "display:flex;gap:8px;margin:4px 0", title: note }, el("input", { type: "checkbox", checked: p[k], onchange: async e => { await api("/settings/privacy", { method: "PUT", body: { [k]: e.target.checked } }); toast(`${k} = ${e.target.checked} (applied now)`); } }), label);
      const filteredSources = Object.entries(h.sources).filter(([k, v]) => k !== "pe_model" || v.status === "available");
      clear(body).append(el("div", { class: "pad" },
        el("h3", {}, "Privacy & telemetry"),
        el("div", { class: "card" }, tog("store_command_lines", "Store command lines (secrets are always redacted)"), tog("redact_paths", "Redact user names in paths"), tog("collect_network", "Collect connection metadata"), tog("collect_registry", "Watch startup (Run) keys"), tog("response_actions_enabled", "Allow response actions (terminate / suspend / quarantine - always confirmed by you, never automatic)"),
          el("label", {}, "Raw event retention (days) ", el("input", { type: "number", min: 1, max: 90, value: p.retention_days_events, style: "width:70px", onchange: async e => { await api("/settings/privacy", { method: "PUT", body: { retention_days_events: +e.target.value } }); } })),
          el("div", { class: "dim", style: "margin-top:6px" }, "All telemetry stays 100% local in SQLite WAL storage. No documents, browser content or keystrokes are ever collected.")),
        el("h3", { style: "margin-top:14px" }, "Telemetry sources"),
        table([{ label: "SOURCE", render: r => r[0] }, { label: "STATE", render: r => el("span", { class: statusCls(r[1].status) }, statusMark(r[1].status) + " " + r[1].status) }, { label: "DETAIL", render: r => fmt.short(r[1].reason, 90) }], filteredSources),
        el("h3", { style: "margin-top:14px" }, "Quarantine"),
        qr.items.length ? table([{ k: "name", label: "FILE" }, { label: "ORIGINAL PATH", render: r => fmt.short(r.original_path, 50) }, { label: "WHEN", render: r => fmt.datetime(r.ts) },
          { label: "", render: r => el("button", { onclick: async () => { try { const x = await api(`/quarantine/${r.id}/restore`, { method: "POST", body: {} }); toast("restored to " + x.restored_to); } catch (e) { toast(e.message, "high"); } draw(); } }, "restore") }], qr.items) : el("div", { class: "dim" }, "nothing in quarantine"),
        el("h3", { style: "margin-top:14px" }, "Allowlist"),
        al.items.length ? table([{ k: "kind", label: "KIND" }, { label: "VALUE", render: r => fmt.short(r.value, 60) }, { k: "reason", label: "REASON" }, { label: "", render: r => el("button", { onclick: async () => { await api(`/allowlist?kind=${r.kind}&value=${encodeURIComponent(r.value)}`, { method: "DELETE" }); draw(); } }, "remove") }], al.items) : el("div", { class: "dim" }, "empty"),
        el("h3", { style: "margin-top:14px" }, "Your data"),
        el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
          el("button", { onclick: async () => download("guardian_export.json", await api("/export")) }, "export investigations (json)"),
          el("button", { onclick: async () => { await api("/collection", { method: "POST", body: { paused: !h.paused } }); toast(h.paused ? "resumed" : "paused"); draw(); } }, h.paused ? "resume collection" : "pause collection"),
          el("button", { class: "danger", onclick: async () => {
            confirmDialog({
              title: "Wipe All Local Telemetry",
              message: "This will permanently delete all raw events, detections, snapshots, network flows, and incident records from local storage. The database schema and settings will be preserved.",
              confirmPrompt: "Type DELETE in capital letters to confirm:",
              placeholder: "DELETE",
              onConfirm: async (val) => {
                if (val !== "DELETE") {
                  toast("Wipe aborted: confirmation text did not match DELETE", "high");
                  return;
                }
                try {
                  await api("/data", { method: "DELETE", body: { confirm: "DELETE" } });
                  toast("Local telemetry deleted cleanly", "low");
                  draw();
                } catch (e) {
                  toast(e.message, "high");
                }
              }
            });
          } }, "delete local data…")),
        el("h3", { style: "margin-top:14px" }, `Audit log  ${au.chain_ok ? "(hash chain verified ✔)" : "(CHAIN BROKEN ✖)"}`),
        table([{ label: "TIME", render: r => fmt.datetime(r.ts) }, { k: "actor", label: "ACTOR" }, { k: "action", label: "ACTION" }, { label: "TARGET", render: r => fmt.short(r.target, 40) }, { k: "result", label: "RESULT" }], au.items.slice(0, 15)),
        el("div", { class: "dim", style: "margin-top:12px" }, `Smart OS Guardian ${h.version} · API loopback only · session token rotates at each start · data: ${h.db.path}`)));
    }
    draw().catch(() => { }); return { destroy() { alive = false; } };
  },
};
