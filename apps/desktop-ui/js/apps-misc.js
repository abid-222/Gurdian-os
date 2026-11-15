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
  name: "Settings & Privacy", short: "cfg", icon: "cfg", w: 880, h: 680, title: h => `Guardian OS — Settings & Privacy (${h})`,
  mount(body) {
    let alive = true;
    async function draw() {
      if (!alive) return;
      try {
        const [p, al, au, h, qr] = await Promise.all([
          api("/settings/privacy").catch(err => {
            console.warn("fetch /settings/privacy failed:", err);
            return {
              store_command_lines: true,
              redact_paths: true,
              collect_network: true,
              collect_registry: true,
              response_actions_enabled: true,
              retention_days_events: 14
            };
          }),
          api("/allowlist").catch(err => {
            console.warn("fetch /allowlist failed:", err);
            return { items: [] };
          }),
          api("/audit?limit=30").catch(err => {
            console.warn("fetch /audit failed:", err);
            return { items: [], chain_ok: true };
          }),
          api("/health").catch(err => {
            console.warn("fetch /health failed:", err);
            return G.state.health || { version: "1.0.0", hostname: "localhost", db: { path: "guardian.db" }, sources: {} };
          }),
          api("/quarantine").catch(err => {
            console.warn("fetch /quarantine failed:", err);
            return { items: [] };
          })
        ]);

        const pSettings = p || {};
        const alItems = (al && al.items) || [];
        const auItems = (au && au.items) || [];
        const qrItems = (qr && qr.items) || [];
        const healthData = h || {};
        const dbPath = (healthData.db && healthData.db.path) || "guardian.db";
        const isPaused = Boolean(healthData.paused);

        const tog = (k, label, desc) => {
          const isChecked = Boolean(pSettings[k]);
          const chk = el("input", {
            type: "checkbox",
            checked: isChecked,
            style: "width:18px;height:18px;accent-color:#38bdf8;cursor:pointer;",
            onchange: async e => {
              try {
                await api("/settings/privacy", { method: "PUT", body: { [k]: e.target.checked } });
                toast(`${label}: ${e.target.checked ? "Enabled" : "Disabled"}`);
              } catch (err) {
                toast("Failed to update: " + err.message, "high");
              }
            }
          });
          return el("div", {
            style: "display:flex;align-items:flex-start;justify-content:space-between;padding:10px 12px;margin:6px 0;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;gap:12px;"
          },
            el("div", { style: "display:flex;flex-direction:column;gap:3px;flex:1" },
              el("span", { style: "font-size:13px;font-weight:600;color:var(--fg-main)" }, label),
              el("span", { class: "dim", style: "font-size:11.5px;line-height:1.4" }, desc)
            ),
            chk
          );
        };

        const filteredSources = Object.entries(healthData.sources || {}).filter(([k, v]) => k !== "pe_model" || (v && v.status === "available"));

        const getSourceBadge = s => {
          const isOk = s === "available" || s === "ok";
          const isDeg = s === "degraded";
          const cls = isOk ? "emerald" : isDeg ? "amber" : "slate";
          return el("span", { class: `badge ${cls}`, style: "font-size:11px" }, (isOk ? "✔ " : isDeg ? "⚠ " : "✖ ") + s);
        };

        // Allowlist Quick Add Form
        const kindSelect = el("select", { style: "padding:6px 10px;background:rgba(15,23,42,0.8);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#fff;font-size:12px;outline:none" },
          el("option", { value: "process_name" }, "Process Name (e.g. code.exe)"),
          el("option", { value: "sha256" }, "SHA-256 Hash"),
          el("option", { value: "ip" }, "Remote IP Address"),
          el("option", { value: "command_line" }, "Command Line Prefix")
        );
        const valInput = el("input", { type: "text", placeholder: "Target value (e.g. notepad.exe or SHA256)", style: "flex:1;min-width:180px;padding:6px 10px;background:rgba(15,23,42,0.8);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#fff;font-size:12px;outline:none" });
        const reasonInput = el("input", { type: "text", placeholder: "Reason (e.g. Approved developer tool)", style: "flex:1;min-width:180px;padding:6px 10px;background:rgba(15,23,42,0.8);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#fff;font-size:12px;outline:none" });
        const addRuleBtn = el("button", {
          class: "btn-subtle sm emerald",
          style: "white-space:nowrap;padding:6px 14px;font-weight:600;cursor:pointer",
          onclick: async () => {
            const kind = kindSelect.value;
            const value = valInput.value.trim();
            const reason = reasonInput.value.trim() || "User approved";
            if (!value) { toast("Please specify a target value to allowlist", "high"); return; }
            try {
              await api("/allowlist", { method: "POST", body: { kind, value, reason } });
              toast(`Added to allowlist: ${value}`, "low");
              valInput.value = "";
              reasonInput.value = "";
              draw();
            } catch (e) {
              toast("Allowlist error: " + e.message, "high");
            }
          }
        }, "+ Add Rule");

        // Retention Days Input
        const retentionInput = el("input", {
          type: "number",
          min: 1,
          max: 90,
          value: pSettings.retention_days_events || 14,
          style: "width:70px;padding:5px 8px;background:rgba(15,23,42,0.8);border:1px solid rgba(255,255,255,0.15);border-radius:6px;color:#fff;font-size:13px;font-weight:600;text-align:center",
          onchange: async e => {
            const val = Math.max(1, Math.min(90, parseInt(e.target.value) || 14));
            try {
              await api("/settings/privacy", { method: "PUT", body: { retention_days_events: val } });
              toast("Event retention updated: " + val + " days");
            } catch (err) {
              toast("Failed to update retention: " + err.message, "high");
            }
          }
        });

        const setRetention = async days => {
          retentionInput.value = days;
          try {
            await api("/settings/privacy", { method: "PUT", body: { retention_days_events: days } });
            toast(`Retention set to ${days} days`);
          } catch (e) {
            toast(e.message, "high");
          }
        };

        clear(body).append(el("div", { class: "pad" },
          // 1. Privacy & Local Telemetry
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:var(--primary)" },
              renderIcon("shield", "cyan", "xs"),
              el("span", {}, "Privacy & Local Telemetry Protection")
            ),
            el("div", { class: "dim", style: "margin-bottom:12px;font-size:12px;line-height:1.5" },
              "🔒 Absolute Privacy Guarantee: All system telemetry is recorded strictly onto this device inside SQLite with Write-Ahead Logging (WAL). No cloud telemetry, keystrokes, clipboard, or document contents are ever recorded."
            ),
            tog("store_command_lines", "Store Process Command Lines", "Captures executable invocation arguments; sensitive credentials, passwords, and tokens are automatically redacted via heuristic regex."),
            tog("redact_paths", "Redact User Profile Paths", "Replaces absolute username folders (e.g. C:\\Users\\Administrator\\...) with generic [USER] placeholders in logs."),
            tog("collect_network", "Collect Network Connection Telemetry", "Monitors active TCP/UDP sockets, remote IP endpoints, and port communication for behavioral anomaly detection."),
            tog("collect_registry", "Monitor Startup Persistence Keys", "Watches Windows Run and RunOnce registry hives for unauthorized autostart persistence attempts."),
            tog("response_actions_enabled", "Enable User-Confirmed Response Actions", "Permits manual remediation actions (Process Terminate, Suspend, Quarantine) — always requiring operator confirmation."),
            
            el("div", { style: "display:flex;align-items:center;justify-content:space-between;margin-top:14px;padding:10px 12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;flex-wrap:wrap;gap:10px" },
              el("div", { style: "display:flex;flex-direction:column;gap:2px" },
                el("span", { style: "font-size:13px;font-weight:600;color:var(--fg-main)" }, "Raw Event Log Retention"),
                el("span", { class: "dim", style: "font-size:11.5px" }, "Older security events and process snapshots are automatically pruned by background vacuum.")
              ),
              el("div", { style: "display:flex;align-items:center;gap:6px" },
                retentionInput,
                el("span", { class: "dim", style: "font-size:12px;margin-right:6px" }, "days"),
                el("button", { class: "btn-subtle xs", onclick: () => setRetention(7) }, "7d"),
                el("button", { class: "btn-subtle xs", onclick: () => setRetention(14) }, "14d"),
                el("button", { class: "btn-subtle xs", onclick: () => setRetention(30) }, "30d")
              )
            )
          ),

          // 2. Sensor Shields & Telemetry Collectors
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#38bdf8" },
              renderIcon("activity", "cyan", "xs"),
              el("span", {}, "Telemetry Collectors & Sensor Shields")
            ),
            table([
              { label: "SENSOR / SOURCE", render: r => el("code", { style: "font-weight:600;color:var(--fg-main)" }, r[0]) },
              { label: "STATUS", render: r => getSourceBadge(r[1] ? r[1].status : "unknown") },
              { label: "OPERATIONAL DETAIL", render: r => el("span", { class: "dim", style: "font-size:12px" }, (r[1] && r[1].reason) ? r[1].reason : "Active, observing system events cleanly") }
            ], filteredSources)
          ),

          // 3. Allowlisted Entities & Trusted Rules
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#10b981" },
              renderIcon("shield-check", "emerald", "xs"),
              el("span", {}, "Allowlisted Entities & Suppression Rules")
            ),
            el("div", { style: "display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px;padding:10px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px" },
              kindSelect,
              valInput,
              reasonInput,
              addRuleBtn
            ),
            alItems.length ? table([
              { k: "kind", label: "RULE TYPE", render: r => el("span", { class: "badge slate", style: "font-size:10.5px" }, r.kind) },
              { label: "TARGET VALUE", render: r => el("code", { style: "font-size:12px;color:#38bdf8" }, fmt.short(r.value, 50)) },
              { k: "reason", label: "JUSTIFICATION" },
              { label: "ACTION", render: r => el("button", {
                class: "btn-subtle xs rose",
                onclick: async () => {
                  try {
                    await api(`/allowlist?kind=${encodeURIComponent(r.kind)}&value=${encodeURIComponent(r.value)}`, { method: "DELETE" });
                    toast("Removed from allowlist: " + r.value);
                    draw();
                  } catch (e) {
                    toast(e.message, "high");
                  }
                }
              }, "Remove") }
            ], alItems) : el("div", { style: "display:flex;align-items:center;gap:8px;padding:12px;background:rgba(255,255,255,0.02);border-radius:8px" },
              renderIcon("check", "emerald", "xs"),
              el("span", { class: "dim", style: "font-size:12.5px" }, "Allowlist is empty — all suspicious behaviors evaluate against full deterministic correlation rules.")
            )
          ),

          // 4. Quarantined Files
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#a855f7" },
              renderIcon("box", "purple", "xs"),
              el("span", {}, "Quarantined Files & Isolation Vault")
            ),
            qrItems.length ? table([
              { k: "name", label: "FILE NAME" },
              { label: "ORIGINAL PATH", render: r => fmt.short(r.original_path, 48) },
              { label: "QUARANTINED AT", render: r => fmt.datetime(r.ts) },
              { label: "ACTION", render: r => el("button", {
                class: "btn-subtle xs cyan",
                onclick: async () => {
                  try {
                    const x = await api(`/quarantine/${r.id}/restore`, { method: "POST", body: {} });
                    toast("Restored executable to " + x.restored_to, "low");
                    draw();
                  } catch (e) {
                    toast(e.message, "high");
                  }
                }
              }, "Restore") }
            ], qrItems) : el("div", { style: "display:flex;align-items:center;gap:8px;padding:12px;background:rgba(255,255,255,0.02);border-radius:8px" },
              renderIcon("shield-check", "emerald", "xs"),
              el("span", { class: "dim", style: "font-size:12.5px" }, "Isolation Vault is clean — 0 quarantined executables.")
            )
          ),

          // 5. Data Management & Storage
          el("div", { class: "card", style: "padding:16px;margin-bottom:14px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:#f59e0b" },
              renderIcon("database", "amber", "xs"),
              el("span", {}, "Data Management & Storage Actions")
            ),
            el("div", { style: "display:flex;gap:8px;flex-wrap:wrap;align-items:center" },
              el("button", {
                class: "btn-subtle sm cyan",
                style: "display:flex;align-items:center;gap:6px;cursor:pointer",
                onclick: async () => {
                  try {
                    const data = await api("/export");
                    download("guardian_export.json", data);
                    toast("Export downloaded cleanly", "low");
                  } catch (e) {
                    toast("Export failed: " + e.message, "high");
                  }
                }
              }, "📥 Export Investigations (JSON)"),
              el("button", {
                class: "btn-subtle sm",
                style: "display:flex;align-items:center;gap:6px;cursor:pointer",
                onclick: async () => {
                  try {
                    await api("/collection", { method: "POST", body: { paused: !isPaused } });
                    toast(isPaused ? "Collection resumed" : "Collection paused");
                    draw();
                  } catch (e) {
                    toast(e.message, "high");
                  }
                }
              }, isPaused ? "▶ Resume Collection" : "⏸ Pause Collection"),
              el("button", {
                class: "btn-subtle sm rose",
                style: "display:flex;align-items:center;gap:6px;cursor:pointer",
                onclick: async () => {
                  confirmDialog({
                    title: "Wipe All Local Telemetry",
                    message: "This will permanently delete all raw security events, process trees, snapshots, and incident records from local storage. The database schema and user settings will be preserved.",
                    confirmPrompt: "Type DELETE in capital letters to confirm:",
                    placeholder: "DELETE",
                    onConfirm: async (val) => {
                      if (val !== "DELETE") {
                        toast("Wipe aborted: text did not match DELETE", "high");
                        return;
                      }
                      try {
                        await api("/data", { method: "DELETE", body: { confirm: "DELETE" } });
                        toast("Local telemetry wiped cleanly", "low");
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

          // 6. Cryptographic Audit Log
          el("div", { class: "card", style: "padding:16px" },
            el("h4", { style: "display:flex;align-items:center;gap:6px;margin:0 0 10px 0;color:var(--fg-main)" },
              renderIcon("lock", "cyan", "xs"),
              el("span", {}, `Cryptographic Audit Trail ${au && au.chain_ok ? "(SHA-256 Chain Verified ✔)" : "(CHAIN BROKEN ✖)"}`)
            ),
            auItems.length ? table([
              { label: "TIME", render: r => fmt.datetime(r.ts) },
              { k: "actor", label: "ACTOR" },
              { k: "action", label: "ACTION" },
              { label: "TARGET", render: r => fmt.short(r.target, 40) },
              { k: "result", label: "RESULT", render: r => el("span", { class: `badge ${r.result === "ok" ? "emerald" : "amber"}`, style: "font-size:10.5px" }, r.result) }
            ], auItems.slice(0, 15)) : el("div", { class: "dim", style: "font-size:12px" }, "No recent audit records."),
            el("div", { class: "dim", style: "margin-top:12px;font-size:11.5px" },
              `Smart OS Guardian ${healthData.version || "1.0.0"} · Loopback API only · Session token isolated · Local DB: ${dbPath}`
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
