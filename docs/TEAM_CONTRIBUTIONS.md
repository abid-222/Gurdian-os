# Smart OS Guardian — Team Project Roles & Viva Distribution

**Course**: Operating Systems (OS) Laboratory  
**Project**: Smart OS Guardian (v0.3.0) — Local Systems Telemetry, Bounded Producer-Consumer Architecture & Guardian Shell  
**Team Structure**: 5 Members (Full-Stack Systems Engineering: Frontend, Backend, OS Architecture & Shell)

---

## Team Overview & System Architecture

```
============================================================================================
                              SMART OS GUARDIAN ARCHITECTURE
============================================================================================

  [ MEMBER 1: Process Lifecycle ]          [ MEMBER 4: Telemetry & I/O ]
   - ProcessCollector (0.5s/2s diffing)     - Network / Sockets (psutil net_connections)
   - PID reuse (PID:create_time key)        - Windows EventLog bookmarks (wevtutil)
   - Signals (terminate, suspend, resume)   - Winreg Run keys (HKEY_CURRENT_USER / HKLM)
   - Critical process shield               - Static PE Shannon entropy & NTFS Zone.Identifier
                     \                                    /
                      ▼                                  ▼
    ========================================================================================
    [ MEMBER 2: Concurrency, Producer-Consumer Bounded Buffer & Thread Synchronization ]
      - EventQueue (10,000 events / 32 MB max)
      - Mutual Exclusion: threading.Lock & threading.RLock
      - Condition Variables: threading.Condition (not_empty wait & notify_all)
      - Priority-Based Load Shedding (Priority 0 alert preserved; Priority 5 shed first)
      - Live Thread Telemetry (Agent.thread_status() tracking 9+ concurrent threads)
    ========================================================================================
                     /                                    \
                    ▼                                      ▼
  [ MEMBER 4: Storage & Crash Recovery ]   [ MEMBER 5: IPC & Frontend GUI ]
   - SQLite WAL (Write-Ahead Logging)       - Loopback REST API + WebSocket push
   - Atomic database migrations             - Parent-Child Process Tree View (apps-proc.js)
   - Corrupt DB isolation & recovery        - Active Threads & Synchronization Dashboard
   - SHA-256 hash-chained audit log         - Evidence timeline & security actions
                    \                                      /
                     ▼                                    ▼
    ========================================================================================
    [ MEMBER 3: Custom Userspace OS Command Interpreter (Guardian Shell) ]
      - Shell Lexical Tokenizer (quotes, backslashes, |, >, >>, <, &)
      - Multi-Stage Pipelines (stdout -> stdin across stages)
      - Sandboxed File I/O Redirection (locked inside data/shell/)
      - Background Job Control: JobManager, daemon threads, jobs, fg, bg, kill
      - Builtin OS filters: pstree, threads, sleep, grep, head, tail, wc, sort, cat, ls
    ========================================================================================
```

---

## Detailed Member Breakdown & Viva Preparation

---

### Member 1: Process Lifecycle Manager & Kernel Protection
* **Title**: Process Management, Process Control Block (PCB) & Signal Control
* **Primary Source Files**:
  - `agent/python-agent/guardian/collectors/processes.py`
  - `agent/python-agent/guardian/response.py`
  - `agent/python-agent/guardian/capabilities.py`
* **Core Responsibilities & Implementation**:
  1. **Dual-Rate Process Sampling (`ProcessCollector`)**:
     - Fast loop (`_tick_fast()`, 0.5s): Diffs live PIDs against known PIDs to detect ephemeral processes before they terminate.
     - Full loop (`_tick_full()`, 2.0s): Refreshes memory RSS, CPU usage, command line, executable path, and parent relationships.
  2. **PID Reuse Protection**:
     - Solves OS PID recycling using a temporal composite key: $\text{key} = \text{PID} : \text{int}(\text{create\_time})$.
  3. **Real Process Control & Signals**:
     - Implemented `terminate_process()` (graceful SIGTERM with SIGKILL fallback), `suspend_process()` (SIGSTOP / `NtSuspendProcess`), and `resume_process()` (SIGCONT / `NtResumeProcess`).
  4. **Protected Process Shield**:
     - Guards vital operating system processes (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `wininit.exe`, `explorer.exe`, PID 0, PID 4).
  5. **Privilege Discovery**:
     - Evaluates administrator rights via `ctypes.windll.shell32.IsUserAnAdmin()` with graceful non-privileged degradation.
* **Viva Talking Points**:
  - *"How does the OS handle PCB sampling without excessive CPU overhead?"* -> Explain dual-rate 0.5s diffing vs 2.0s full PCB scan.
  - *"Why is PID reuse dangerous in security telemetry, and how did you solve it?"* -> Explain temporal composite key disambiguation.
  - *"How are processes suspended and resumed at the OS level?"* -> Explain userspace signals and Windows `NtSuspendProcess`/`NtResumeProcess` APIs.

---

### Member 2: Concurrency & Synchronization Specialist
* **Title**: Multithreading Architecture, Producer-Consumer Bounded Queue & Condition Variables
* **Primary Source Files**:
  - `agent/python-agent/guardian/queue.py`
  - `agent/python-agent/guardian/agent.py`
  - `agent/python-agent/guardian/collectors/base.py`
* **Core Responsibilities & Implementation**:
  1. **Producer-Consumer Bounded Buffer (`EventQueue`)**:
     - Implemented a circular FIFO queue bounded to `10,000` events and `32 MB` memory.
  2. **Synchronization Primitives**:
     - `threading.Lock` protects queue counters and internal deque.
     - `threading.Condition` (`self.not_empty`) prevents consumer busy-waiting (`wait()` when empty, `notify_all()` on insert).
  3. **Priority-Based Load Shedding**:
     - At 70% capacity, triggers warning state.
     - At 90% capacity, initiates priority shedding: drops Priority 5 (`image_load`) first, while Priority 0 (`alert`, `sensor_tamper`) is never discarded.
  4. **Live Thread Telemetry Engine**:
     - Engineered `Agent.thread_status(self) -> list[dict]` tracking all 9+ concurrent threads (5 producers, 2 consumers, 1 worker, 1 watchdog) with live states, heartbeat ages, intervals, and error counters.
* **Viva Talking Points**:
  - *"How do you solve the classical Producer-Consumer problem in this project?"* -> Explain `EventQueue` with `Condition` variables and bounded buffer.
  - *"What happens when the system is under heavy load?"* -> Explain priority load shedding and backpressure.
  - *"How do you prevent deadlocks between threads?"* -> Explain lock ordering and re-entrant `RLock` in storage transactions.

---

### Member 3: Custom Userspace Shell & Command Interpreter Developer
* **Title**: Shell Lexer, Multi-Stage Pipelines, Sandboxed I/O Redirection & Job Control
* **Primary Source Files**:
  - `agent/python-agent/guardian/commands.py`
  - `apps/desktop-ui/js/apps-terminal.js`
* **Core Responsibilities & Implementation**:
  1. **Lexical Parser & Tokenizer**:
     - `tokenize_shell()` handles token recognition for pipes (`|`), redirection (`>`, `>>`, `<`), background operator (`&`), while preserving quoted paths and Windows backslashes.
  2. **Pipeline Execution Engine**:
     - Executes multi-stage pipelines (`execute_pipeline()`), passing stdout of stage $i$ as stdin to stage $i+1$.
     - Example: `processes --top 15 | grep python | wc`.
  3. **Sandboxed File I/O Redirection**:
     - Confines `<, >, >>` strictly inside `data/shell/` with directory traversal protection (`_safe_shell_path`).
  4. **Background Job Manager (`JobManager`)**:
     - Running `cmd &` spawns a background daemon thread tracked with Job ID (`[1]`, `[2]`).
     - Supports `jobs`, `fg <id>` (bring to foreground & wait), `bg <id>` (resume), and `kill <id>` (cancellation via `threading.Event`).
  5. **Custom OS Filter Builtins**:
     - Implemented `pstree` (ASCII parent-child tree), `threads`, `wc`, `grep [-i]`, `head [-n]`, `tail [-n]`, `sort [-r]`, `cat`, `ls`, `sleep`, `echo`.
* **Viva Talking Points**:
  - *"How does your shell parse command tokens and handle pipelines?"* -> Walk through `tokenize_shell()` and stage chaining in `execute_pipeline()`.
  - *"How are background jobs tracked and killed cooperatively?"* -> Explain daemon threads, `JobManager`, and `job.cancel_event`.
  - *"How do you prevent path traversal attacks in file redirection?"* -> Explain `_safe_shell_path()` sandbox validation.

---

### Member 4: Telemetry, I/O & Storage Engineer
* **Title**: OS Telemetry Collectors, SQLite WAL Mode, Crash Recovery & File Intelligence
* **Primary Source Files**:
  - `agent/python-agent/guardian/db.py`
  - `agent/python-agent/guardian/collectors/network.py`
  - `agent/python-agent/guardian/collectors/winevents.py`
  - `agent/python-agent/guardian/collectors/registry.py`
  - `agent/python-agent/guardian/pe.py`
* **Core Responsibilities & Implementation**:
  1. **Crash-Resilient Storage (SQLite WAL Mode)**:
     - Configured Write-Ahead Logging (`PRAGMA journal_mode=WAL`) allowing concurrent readers alongside the dedicated batch writer.
     - Implemented atomic schema migrations and automatic DB corruption recovery (isolates corrupted file as `db.corrupt-*.db` and reinitializes cleanly).
  2. **Cryptographic Tamper-Evident Audit Chain**:
     - Implemented SHA-256 hash chaining on all sensitive actions (`Database.audit` and `verify_audit_chain`).
  3. **OS Telemetry Collectors**:
     - Network connection polling and local socket table mapping.
     - Windows Event Log bookmarking (`wevtutil`) preventing duplicate event ingestion across restarts.
     - Windows Registry monitoring (`winreg`) detecting unauthorized auto-start persistence (`Run` keys).
  4. **Static File Intelligence**:
     - Shannon entropy calculation ($H = -\sum p \log_2 p$) for detecting packed/encrypted PE sections.
     - NTFS Alternate Data Streams inspection (`:Zone.Identifier`) to determine origin zone (e.g. Internet downloads).
* **Viva Talking Points**:
  - *"Why is Write-Ahead Logging (WAL) important for OS database concurrency?"* -> Explain reader-writer concurrency without table locks.
  - *"How does your tamper-evident audit log detect unauthorized database modifications?"* -> Explain the SHA-256 cryptographic hash chain.
  - *"What is Shannon entropy in static PE file inspection?"* -> Explain measure of randomness for packed executables.

---

### Member 5: Frontend Systems Architect & Desktop UI Developer
* **Title**: Inter-Process Communication (IPC), Desktop Web Shell & Real-Time Dashboards
* **Primary Source Files**:
  - `apps/desktop-ui/js/apps-home.js`
  - `apps/desktop-ui/js/apps-proc.js`
  - `apps/desktop-ui/js/apps-sec.js`
  - `apps/desktop-ui/js/apps-misc.js`
  - `agent/python-agent/guardian/api.py`
* **Core Responsibilities & Implementation**:
  1. **Inter-Process Communication (IPC)**:
     - Connected the Python backend to the desktop frontend using a loopback REST API and WebSockets on `127.0.0.1`.
     - Integrated thread-safe event push via `asyncio.Queue` and `loop.call_soon_threadsafe()`.
  2. **Active Threads & Synchronization Dashboard**:
     - Built the live **"Active OS Agent Threads & Synchronization"** panel displaying thread roles, states (`[ OK ]`), synchronization primitives, and heartbeat ages.
     - Designed the live **Pipeline & Bounded Queue** card showing fill gauge, event depth, bytes, and dropped count.
  3. **Parent-Child Process Tree UI**:
     - Enabled Tree View by default (`st.tree = true`) with prominent menubar toggle `🌳 Process Tree: ON (F5)`.
     - Implemented cycle-free tree walk (`visited` set) with parent fallback (`parent_key` -> `ppid` -> `pid`) and child count badges `(N)`.
     - Added interactive child process navigation in the process detail pane.
  4. **Security Center & File Inspector**:
     - Built real-time incident timeline, evidence correlation viewers, and static file inspection interface.
* **Viva Talking Points**:
  - *"How does the frontend communicate with backend OS threads asynchronously?"* -> Explain REST endpoints, WebSockets, and `call_soon_threadsafe()`.
  - *"How is the parent-child process tree rendered in the UI without browser lockups or infinite recursion?"* -> Explain `order(items)` with Map lookups and `visited` Set.
  - *"How are thread synchronization metrics rendered in real time?"* -> Explain periodic poll + WebSocket event updates.

---

## Team Checklist for Defense / Viva Day

| Item | Responsible Member | Verification Command / Action |
|---|---|---|
| Process Management & Signals | Member 1 | Run Process Center, suspend/resume a process, inspect PID keys |
| Producer-Consumer Bounded Queue | Member 2 | Open Home dashboard, inspect bounded queue fill % and thread table |
| Guardian Shell Pipelines & Jobs | Member 3 | Open Guardian Shell: `processes \| grep python \| wc`, `sleep 5 &`, `jobs` |
| SQLite WAL & Audit Chain | Member 4 | Run `Database.verify_audit_chain()`, inspect `data/*.db` WAL files |
| Desktop UI & Process Tree | Member 5 | Open Process Center, verify tree hierarchy `├─`, `└─`, and child badges |
| Automated Test Suite | All Members | Run `pytest tests` (all 32 tests pass) & `python -m guardian.selfcheck` |
