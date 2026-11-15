# Project Status (v1.0.0 Release) — Operating Systems Lab Focus & Production Readiness

Legend: **VERIFIED (v1.0)** = Implemented, security-hardened, and regression-tested across all automated suites.

| OS Subsystem / Module | State | Notes |
|---|---|---|
| **Process Collector & PCB Sampling** | VERIFIED (v1.0) | Dual-rate diffing: 0.5s fast PID diffing for short-lived processes + 2.0s full PCB scan (CPU, RSS, start_time, parent). |
| **PID Reuse Protection** | VERIFIED (v1.0) | Temporal disambiguation key `PID:start_ts` prevents telemetry collision when OS reuses PIDs. |
| **Process Tree & Hierarchy** | VERIFIED (v1.0) | ASCII process tree reconstruction (`pstree`) in CLI and Parent-Child Tree view with child badges `(N)` in Desktop UI. |
| **Process Control & Signals** | VERIFIED (v1.0) | Userspace process signals (`Terminate`, `Suspend`, `Resume`, `Quarantine`) with critical OS process protections and non-blocking modal confirmation dialogs. |
| **Multithreading & Concurrency** | VERIFIED (v1.0) | Asynchronous collectors, dedicated database writer, correlation engine, hash worker, and heartbeat watchdog. Graceful joining with bounded 1.0s timeouts on shutdown. |
| **Live Thread Telemetry** | VERIFIED (v1.0) | `Agent.thread_status()` exposing producer/consumer roles, liveness, heartbeat age, and sync primitives live on Home dashboard. |
| **Bounded Event Queue** | VERIFIED (v1.0) | 10,000 events / 32 MB buffer with `threading.Lock` and `threading.Condition`, backpressure, clamped byte accounting, and priority load shedding. |
| **Guardian Shell (Command Interpreter)**| VERIFIED (v1.0) | Shell lexer/tokenizer, multi-stage pipelines (`|`), sandboxed redirection (`>`, `>>`, `<`), and job control (`&`, `jobs`, `fg`, `bg`, `kill`). |
| **Storage Engine (SQLite WAL)** | VERIFIED (v1.0) | WAL mode for concurrent readers and writer; sequential atomic migrations; retention cleanup; clean `wal_checkpoint(TRUNCATE)` on exit. |
| **Crash & Corruption Recovery** | VERIFIED (v1.0) | Automatic quarantine of corrupted SQLite files (`db.corrupt-*.db`), seamless fresh initialization, and recovery auditing. |
| **File Intelligence & Metadata** | VERIFIED (v1.0) | Static PE header parsing, Shannon entropy calculation, DLL imports extraction, Authenticode verification, and NTFS `:Zone.Identifier`. |
| **Security & Cryptographic Audit** | VERIFIED (v1.0) | Loopback isolation, rotating 256-bit token authentication, path traversal protection, and SHA-256 hash-chained tamper-evident audit logging. |
| **Rules Correlation Engine** | VERIFIED (v1.0) | Deterministic OS rules E2–E6 correlating process spawns, network flows, persistence, and log-clearing incidents into explainable alerts. |
| **Decoupled ML Architecture** | VERIFIED (v1.0) | Heavy ML dependencies moved to `optional/` so core OS runtime runs 100% lightweight and dependency-free. |
| **Desktop Workstation UI/UX** | VERIFIED (v1.0) | Framed Glassmorphic Bento Grid workstation with 3D squircle SVG icon system, zero-freeze modals, and universal ESC handling. |

---

## Known Limits & Design Choices
* **Polling Latency**: Fast-path PID polling operates at 0.5s intervals. Processes that exit in under 50ms without generating Event Log records may be missed unless Windows Sysmon is installed.
* **Non-Privileged Mode**: Running without Administrator privileges gracefully disables reading the Windows Security Event Log, while process, network, and registry monitoring remain fully operational.
* **Userspace Command Shell**: Arbitrary host command execution is intentionally disabled in Guardian Shell for sandboxing and security.
