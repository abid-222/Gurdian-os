# Guardian OS — Frontend Integration Report
**Date**: November 15, 2026  
**Status**: 100% Connected & Verified  

---

## 1. Application Screen to Backend Endpoint Matrix

| Application Screen | File | Primary API Endpoints | Real-Time Transport | User Interactive Actions |
|---|---|---|---|---|
| **1. Overview Dashboard** | `apps-home.js` | `/health`, `/system/summary`, `/alerts?limit=5`, `/collection` | WebSocket (`health`, `events`) | Pause/Resume collection, quick launches, shield inspection |
| **2. Process Explorer** | `apps-proc.js` | `/processes`, `/processes/{key}`, `/actions/preview`, `/actions/execute` | Polling (2.5s) + diffing | Parent/Child tree toggle, terminate, suspend, resume, quarantine, scan file, allowlist |
| **3. Thread Monitor** | `apps-home.js`, `apps-misc.js` | `/health` (`threads`), `/system/summary` | WebSocket push | Producer-Consumer buffer depth, condition variable inspection |
| **4. Security Center** | `apps-sec.js` | `/alerts`, `/alerts/{id}`, `/alerts/{id}/acknowledge`, `/alerts/{id}/dismiss`, `/alerts/{id}/notes` | WebSocket incident toasts | Acknowledge, dismiss (with audited reason dialog), add investigation notes, export JSON |
| **5. Network Monitor** | `apps-proc.js` | `/network/connections`, `/network/flows` | Polling (3.0s) | Search filter, Live sockets vs DB history toggle, export view |
| **6. File Intelligence** | `apps-misc.js` | `/models`, `/scan` | On-demand REST POST | Static PE header parsing, Shannon entropy, imports, Authenticode verification |
| **7. Guardian Shell** | `apps-terminal.js` | `/terminal`, `/health`, `/system/summary` | WebSocket / REST execution | Pipes, redirection, background jobs, history navigation, tab completion |
| **8. Audit & Recovery** | `apps-misc.js` | `/audit`, `/quarantine`, `/quarantine/{id}/restore` | Polling (4.0s) | Tamper-evident hash chain verification, quarantine restore |
| **9. Settings & Diagnostics** | `apps-misc.js` | `/settings/privacy`, `/allowlist`, `/data` | Immediate REST PUT/DELETE | Telemetry toggles, retention slider, allowlist removal, database wipe |

---

## 2. Integration Verification Checklist

- [x] All 9 application modules communicate with genuine backend endpoints (Zero mock data).
- [x] All process and incident actions routed through guarded backend endpoints.
- [x] WebSocket auto-reconnects on disconnection.
- [x] Non-blocking modal dialogs replace raw browser prompts.
- [x] Universal ESC key closes topmost modals and active windows smoothly.
