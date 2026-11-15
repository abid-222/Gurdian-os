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
          if (r.model && r.model.top_features && r.model.top_features.length) {
            rows.splice(10, 0, ["SHAP Attribution", r.model.top_features.map(x => `${x.feature} (${x.impact > 0 ? "+" : ""}${x.impact})`).join(" • ")]);
          }

          const shapCard = (r.model && r.model.top_features && r.model.top_features.length) ? el("div", {
            class: "card",
            style: "margin-top:10px;border-left:3px solid #38bdf8;background:rgba(56,189,248,0.06)"
          },
            el("h4", { style: "display:flex;align-items:center;gap:6px;color:#38bdf8;margin:0 0 8px 0" },
              renderIcon("shield-alert", "cyan", "xs"),
              el("span", {}, "AI Feature Attribution & Explainability (LightGBM SHAP Values):")
            ),
            el("div", { class: "dim", style: "font-size:12px;margin-bottom:8px" },
              "Detailed mathematical SHAP attribution explaining why the ML model scored this PE binary:"
            ),
            el("div", { style: "display:flex;flex-direction:column;gap:6px" },
              ...r.model.top_features.map((feat, idx) => el("div", {
                style: "display:flex;align-items:center;justify-content:space-between;padding:6px 10px;background:rgba(255,255,255,0.03);border-radius:6px"
              },
                el("div", { style: "display:flex;align-items:center;gap:8px" },
                  el("span", { class: "device-chip", style: "font-size:10px;padding:1px 6px" }, `#${idx + 1}`),
                  el("span", { style: "font-weight:600;font-size:13px" }, feat.feature)
                ),
                el("div", { style: "display:flex;align-items:center;gap:8px" },
                  el("span", { class: feat.impact > 0 ? "st-bad" : "st-ok", style: "font-weight:700;font-family:var(--font-mono)" },
                    (feat.impact > 0 ? "+" : "") + feat.impact
                  ),
                  el("span", { class: "badge " + (feat.impact > 0 ? "rose" : "emerald"), style: "font-size:10px" },
                    feat.impact > 0 ? "Malicious Factor" : "Benign Factor"
                  )
                )
              ))
            )
          ) : null;

          clear(out).append(
            kv(rows),
            shapCard,
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

      const quickSamples = [
        "C:\\Windows\\explorer.exe",
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
      ];

      const sampleButtons = el("div", { style: "display:flex;gap:6px;align-items:center;margin:8px 0;flex-wrap:wrap" },
        el("span", { class: "dim", style: "font-size:12px" }, "Quick Test Targets:"),
        ...quickSamples.map(target => el("button", {
          class: "btn-subtle xs cyan",
          style: "font-size:11px;padding:3px 8px;font-family:var(--font-mono)",
          title: "Scan " + target,
          onclick: () => {
            pathIn.value = target;
            scan();
          }
        }, target.split("\\").pop()))
      );

      clear(body).append(el("div", { class: "pad" },
        el("div", { class: "card", style: "padding:16px" },
          el("div", { style: "display:flex;align-items:center;gap:8px;margin-bottom:6px" },
            renderIcon("file-search", "cyan", "sm"),
            el("h4", { style: "margin:0;font-size:15px;color:#fff" }, "File Intelligence & Static PE Inspection"),
            el("span", { class: "badge emerald", style: "font-size:10px" }, "Safe: Zero Detonation")
          ),
          el("div", { class: "dim", style: "margin-bottom:12px;font-size:12.5px;line-height:1.5" },
            "Files are analyzed strictly via static header parsing — never executed. Extracts SHA-256 cryptographic hash, PE header sections, Shannon entropy, API imports table, Authenticode digital signature, and NTFS Mark-of-the-Web (Zone.Identifier) stream."
          ),
          sampleButtons,
          el("div", { style: "display:flex;gap:8px;align-items:center;margin-top:6px" },
            pathIn,
            el("button", { class: "btn-primary", style: "white-space:nowrap;padding:8px 16px;cursor:pointer", onclick: scan }, "🔍 Inspect File")
          ),
          out
        ),

        el("div", { class: "card", style: "margin-top:14px;padding:14px" },
          el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:var(--primary)" },
            renderIcon("shield-check", "cyan", "xs"),
            el("span", {}, "Detection Engine & Intelligence Architecture")
          ),
          el("div", { class: "grid3", style: "gap:10px" },
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px;font-size:12px" },
              el("strong", { style: "color:#34d399;display:block;margin-bottom:3px" }, "✔ Deterministic Rules E2–E6:"),
              el("span", { class: "dim" }, "Active real-time temporal correlation across process lineage, parent-child anomalies, persistence, and network connections.")
            ),
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px;font-size:12px" },
              el("strong", { style: "color:#38bdf8;display:block;margin-bottom:3px" }, "✔ Static Heuristic Engine:"),
              el("span", { class: "dim" }, "Shannon entropy calculation, suspicious W+X sections detection, Authenticode signature check, and memory injection API spotting.")
            ),
            el("div", { style: "background:rgba(255,255,255,0.02);padding:10px;border-radius:8px;font-size:12px" },
              el("strong", { style: "color:#c084fc;display:block;margin-bottom:3px" }, a ? "✔ E1 ML Static Model:" : "ℹ E1 Model Slot:"),
              el("span", { class: "dim" }, a ? `${a.model_id} v${a.version} loaded and scoring` : "Rules-first architecture. Deterministic behavioral security operates with zero ML dependency.")
            )
          )
        )
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
      if (!alive) return;
      try {
        const [p, al, au, h, qr] = await Promise.all([
          api("/settings/privacy"),
          api("/allowlist"),
          api("/audit?limit=30"),
          api("/health"),
          api("/quarantine")
        ]);

        const tog = (k, label, note) => el("label", { style: "display:flex;gap:8px;margin:5px 0;align-items:center;cursor:pointer", title: note },
          el("input", {
            type: "checkbox",
            checked: p[k],
            onchange: async e => {
              await api("/settings/privacy", { method: "PUT", body: { [k]: e.target.checked } });
              toast(`${k} = ${e.target.checked} (applied now)`);
            }
          }),
          el("span", { style: "font-size:13px" }, label)
        );

        const filteredSources = Object.entries(h.sources || {}).filter(([k, v]) => k !== "pe_model" || v.status === "available");

        const getSourceBadge = s => {
          const isOk = s === "available" || s === "ok";
          const isDeg = s === "degraded";
          const cls = isOk ? "emerald" : isDeg ? "amber" : "slate";
          return el("span", { class: `badge ${cls}`, style: "font-size:11px" }, (isOk ? "✔ " : isDeg ? "⚠ " : "✖ ") + s);
        };

        clear(body).append(el("div", { class: "pad" },
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:var(--primary)" },
              renderIcon("shield", "cyan", "xs"),
              el("span", {}, "Privacy & Local Telemetry")
            ),
            tog("store_command_lines", "Store process command lines (sensitive tokens/passwords automatically redacted)"),
            tog("redact_paths", "Redact user profile names in absolute file paths"),
            tog("collect_network", "Collect outbound and inbound TCP connection metadata"),
            tog("collect_registry", "Monitor startup persistence (Windows Run / RunOnce keys)"),
            tog("response_actions_enabled", "Enable incident response capabilities (terminate, suspend, quarantine — always user-confirmed)"),
            el("div", { style: "display:flex;align-items:center;gap:8px;margin-top:10px" },
              el("label", { style: "font-size:13px" }, "Raw event retention (days): "),
              el("input", {
                type: "number",
                min: 1,
                max: 90,
                value: p.retention_days_events || 7,
                style: "width:75px",
                onchange: async e => {
                  await api("/settings/privacy", { method: "PUT", body: { retention_days_events: +e.target.value } });
                  toast("Retention updated: " + e.target.value + " days");
                }
              })
            ),
            el("div", { class: "dim", style: "margin-top:8px;font-size:12px" },
              "🔒 Absolute Data Privacy: All telemetry stays 100% local inside the SQLite WAL database. No network beaconing, cloud telemetry, keystroke logging, or document contents are ever collected."
            )
          ),

          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#38bdf8" },
              renderIcon("activity", "cyan", "xs"),
              el("span", {}, "Telemetry Collectors & Sensor Shields")
            ),
            table([
              { label: "SENSOR / SOURCE", render: r => el("code", { style: "font-weight:600" }, r[0]) },
              { label: "STATUS", render: r => getSourceBadge(r[1].status) },
              { label: "OPERATIONAL DETAIL", render: r => el("span", { class: "dim", style: "font-size:12px" }, r[1].reason || "Active and healthy") }
            ], filteredSources)
          ),

          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#a855f7" },
              renderIcon("box", "purple", "xs"),
              el("span", {}, "Quarantined Files")
            ),
            (qr.items && qr.items.length) ? table([
              { k: "name", label: "FILE" },
              { label: "ORIGINAL PATH", render: r => fmt.short(r.original_path, 50) },
              { label: "WHEN", render: r => fmt.datetime(r.ts) },
              { label: "", render: r => el("button", {
                class: "btn-subtle xs cyan",
                onclick: async () => {
                  try {
                    const x = await api(`/quarantine/${r.id}/restore`, { method: "POST", body: {} });
                    toast("Restored to " + x.restored_to);
                    draw();
                  } catch (e) {
                    toast(e.message, "high");
                  }
                }
              }, "Restore") }
            ], qr.items) : el("div", { class: "dim", style: "font-size:12px" }, "No files currently quarantined.")
          ),

          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#10b981" },
              renderIcon("shield-check", "emerald", "xs"),
              el("span", {}, "Allowlisted Entities")
            ),
            (al.items && al.items.length) ? table([
              { k: "kind", label: "KIND" },
              { label: "VALUE", render: r => fmt.short(r.value, 60) },
              { k: "reason", label: "REASON" },
              { label: "", render: r => el("button", {
                class: "btn-subtle xs rose",
                onclick: async () => {
                  await api(`/allowlist?kind=${r.kind}&value=${encodeURIComponent(r.value)}`, { method: "DELETE" });
                  toast("Removed from allowlist");
                  draw();
                }
              }, "Remove") }
            ], al.items) : el("div", { class: "dim", style: "font-size:12px" }, "Allowlist is empty.")
          ),

          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#f59e0b" },
              renderIcon("database", "amber", "xs"),
              el("span", {}, "Data Management & Storage Actions")
            ),
            el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
              el("button", {
                class: "btn-subtle sm cyan",
                onclick: async () => download("guardian_export.json", await api("/export"))
              }, "Export Investigations (JSON)"),
              el("button", {
                class: "btn-subtle sm",
                onclick: async () => {
                  await api("/collection", { method: "POST", body: { paused: !h.paused } });
                  toast(h.paused ? "Collection resumed" : "Collection paused");
                  draw();
                }
              }, h.paused ? "▶ Resume Collection" : "⏸ Pause Collection"),
              el("button", {
                class: "btn-subtle sm rose",
                onclick: async () => {
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
                }
              }, "🗑 Delete Local Telemetry…")
            )
          ),

          el("div", { class: "card", style: "padding:16px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:var(--fg-main)" },
              renderIcon("lock", "cyan", "xs"),
              el("span", {}, `Cryptographic Audit Log ${au.chain_ok ? "(Hash Chain Verified ✔)" : "(CHAIN BROKEN ✖)"}`)
            ),
            table([
              { label: "TIME", render: r => fmt.datetime(r.ts) },
              { k: "actor", label: "ACTOR" },
              { k: "action", label: "ACTION" },
              { label: "TARGET", render: r => fmt.short(r.target, 40) },
              { k: "result", label: "RESULT" }
            ], (au.items || []).slice(0, 15)),
            el("div", { class: "dim", style: "margin-top:12px;font-size:11.5px" },
              `Smart OS Guardian ${h.version} · API loopback only · session token rotates on start · DB: ${h.db.path}`
            )
          )
        ));
      } catch (err) {
        console.error("Settings error:", err);
        clear(body).append(
          el("div", { class: "pad st-bad" }, "Settings load error: " + err.message)
        );
      }
    }
    draw();
    return { destroy() { alive = false; } };
  },
};
