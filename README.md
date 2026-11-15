# Smart OS Guardian

**Operating Systems (OS) Lab Project: Local Endpoint Telemetry, Bounded Producer-Consumer Architecture & Guardian Shell**

Smart OS Guardian is a local systems programming and operating systems project for Windows (also runs on Linux/macOS in developer mode). It implements real-time process monitoring, multithreaded telemetry collection, a synchronized bounded buffer queue with priority load shedding, process lifecycle management, a userspace command shell with pipelines and job control, and crash-resilient storage.

> **OS Defense & Viva Guide**: For a detailed mapping of every OS concept (PCB, Producer-Consumer synchronization, Condition Variables, Pipelines, Job Control, IPC, and Crash Recovery) to exact code files and functions, see [**`docs/OS_CONCEPTS.md`**](docs/OS_CONCEPTS.md).

---

## Core OS Concepts Demonstrated

| Operating System Domain | Implementation Highlights |
|---|---|
| **Process Management & PCB** | Dual-rate process sampling (0.5s fast PID diffing + 2.0s full PCB scan), PID reuse disambiguation (`PID:start_time`), and ASCII process tree reconstruction (`pstree`). |
| **Threads & Concurrency** | Dedicated background threads for producers (`processes`, `network`, `resources`, `winevents`, `registry`), consumers (`writer`, `engine`), worker (`enricher`), and watchdog (`heartbeat`). |
| **Bounded Queue & Synchronization** | Producer-Consumer bounded queue (`10,000` events / `32 MB`) using `threading.Lock` and `threading.Condition` variables, with backpressure and priority load shedding. |
| **Guardian Shell (Command Interpreter)** | Userspace lexical tokenizer, pipelines (`|`), sandboxed file redirection (`>`, `>>`, `<`), and background job control (`&`, `jobs`, `fg`, `bg`, `kill`). |
| **Process Control & Signals** | User-controlled `Terminate`, `Suspend` (SIGSTOP), `Resume` (SIGCONT), and safe file `Quarantine`, with critical kernel/OS process guards. |
| **Storage & Crash Recovery** | SQLite Write-Ahead Logging (WAL) for concurrent read/write transactions, schema migrations, and automatic corruption recovery. |
| **Security & Auditing** | Loopback-only REST/WebSocket API with rotating session tokens, least-privilege degradation, and SHA-256 hash-chained tamper-evident audit logs. |

---

## Architecture Overview

```
[OS Telemetry Producers]                [Bounded Queue]             [Consumers & Engine]
  ├─ Process Collector (0.5s / 2.0s) ───┐
  ├─ Network Collector (2.0s)        ───┼─► EventQueue (10k / 32MB) ───┬─► DB Batch Writer (WAL)
  ├─ Resource Collector (2.0s)       ───┤   (Lock + Condition Var)    └─► Correlation Engine (Rules E2-E6)
  ├─ Windows Event Collector (2.0s)  ───┤   (Priority Load Shedding)
  └─ Registry Collector (5.0s)       ───┘

[Userspace Guardian Shell]
  └─ Lexer ──► Pipelines (|) ──► Sandboxed Redirection (>, >>, <) ──► JobManager (&, jobs, fg, bg, kill)
```

---

## Team Contributions & Work Distribution (5 Members)

Detailed defense breakdown available in [**`docs/TEAM_CONTRIBUTIONS.md`**](docs/TEAM_CONTRIBUTIONS.md).

| Member | Focus Domain | Primary Modules & Contributions |
|---|---|---|
| **Member 1** | **Process Lifecycle & Signals** | `processes.py`, `response.py`: 0.5s/2s dual-rate diffing, `PID:start_ts` reuse protection, `terminate`/`suspend`/`resume`/`quarantine` controls, and kernel process protection. |
| **Member 2** | **Concurrency & Synchronization** | `queue.py`, `agent.py`: Bounded buffer `EventQueue` (10k / 32MB), `threading.Lock` + `threading.Condition` variables, priority load shedding, and `Agent.thread_status()`. |
| **Member 3** | **Guardian Shell & Interpreter** | `commands.py`, `apps-terminal.js`: Tokenizer, multi-stage pipelines (`\|`), sandboxed file redirection (`>`, `>>`, `<`), background `JobManager` (`&`, `jobs`, `fg`, `bg`, `kill`), and OS builtins (`pstree`, `threads`, `wc`, `grep`). |
| **Member 4** | **Telemetry, I/O & Storage** | `db.py`, `network.py`, `winevents.py`, `registry.py`, `pe.py`: SQLite WAL mode, crash recovery, EventLog bookmarking, winreg auto-start diffing, Shannon entropy, and hash-chained audit log. |
| **Member 5** | **Frontend GUI & IPC Systems** | `apps-home.js`, `apps-proc.js`, `apps-sec.js`, `api.py`: Loopback REST & WebSocket push, Parent-Child Process Tree view (`🌳 F5`), Live Thread Synchronization dashboard, and evidence timeline. |

---

## Quickstart (Windows 10/11, Python 3.10–3.12)

1. **Install Dependencies**:
   ```cmd
   install.bat
   ```
   *Creates virtual environment and installs core runtime packages.*

2. **Run Guardian**:
   ```cmd
   run.bat
   ```
   *(Or `run_admin.bat` for full Security Event Log and elevated process path access).*

3. **Verify System**:
   ```cmd
   check.bat
   ```
   *(Or run `pytest tests`).*

Linux/macOS developer mode: `./run_dev.sh`.

---

## Guardian Shell Commands

Guardian Shell provides a safe, controlled command interpreter demonstrating shell parsing and process management without executing arbitrary host commands:

```bash
# Pipelines and text filters
processes --top 15 | grep python | wc
pstree | grep explorer

# Sandboxed file I/O redirection (restricted to data/shell/)
echo "log test" > test.txt
cat < test.txt | grep test

# Background job control
sleep 10 &
jobs
kill 1
```

---

## Optional Machine Learning Module

To maintain focus on core Operating Systems fundamentals and avoid heavy ML dependencies (`lightgbm`, `scikit-learn`, `numpy`), all machine learning components and datasets are decoupled into the **[`optional/`](optional/)** directory:
- Main runtime operates deterministically on **OS Rules E2–E6** and static File Intelligence (SHA-256, Shannon entropy, Authenticode signatures, and NTFS Zone.Identifier streams).
- The E1 ML slot remains available as an optional add-on without affecting the core OS demonstration.

---

## Verification & Testing

* **Unit & Integration Tests**:
  ```cmd
  pytest tests
  ```
* **Self-Check Diagnostic**:
  ```cmd
  python -m guardian.selfcheck
  ```
* **Live Scenarios**:
  ```cmd
  python testbed/run_real_scenarios.py
  ```
* **Performance Benchmark**:
  ```cmd
  python tools/benchmark.py
  ```
