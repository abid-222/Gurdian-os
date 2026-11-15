# Architecture (as built)
```
Windows sources ──> collectors (threads) ──> normalise+redact ──> bounded queue ──> writer (batch txn) ──> SQLite(WAL)
 psutil / wevtutil / winreg / Sysmon                     │                                   │
                                                         └── engine: rules ─> detections ─> correlation (policy v1) ─> incidents
FastAPI (127.0.0.1, token) <── reads prepared data ── agent;   UI (static JS) ── HTTP + WebSocket ──> API only
```
* UI never touches OS sources or the DB. Collector failure never stops the agent; each source has a heartbeat and a capability state.
* Evidence classes E1–E6, join key process_key (pid + start time), merge by parent-child chain and same SHA-256 within 600 s.
* Severity: Informational stays a quiet timeline entry; Low+ becomes an incident. Critical needs a validated high-precision rule (none ship in the MVP).
* Tuning deviation from the literal policy text: `medium_requires_non_weak=true` (two weak classes alone stay Informational) to avoid alert fatigue. Set false to ablate (A-series).
