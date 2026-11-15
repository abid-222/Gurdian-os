# Smart OS Guardian — Operating System Concepts & Implementation Guide

This document is an academic reference mapping core **Operating System (OS)** principles to their concrete implementations in `smart-os-guardian`. It is designed as an OS Laboratory defense and viva reference guide.

---

## Quick Reference Table

| OS Concept | Primary Implementation File | Key Classes & Functions |
|---|---|---|
| **Process Management & PCB** | `agent/python-agent/guardian/collectors/processes.py` | `ProcessCollector`, `_tick_fast()`, `_tick_full()`, `_make_pi()` |
| **PID Reuse Protection** | `agent/python-agent/guardian/collectors/processes.py` | `key = f"{pid}:{int(create_time)}"` |
| **Process Tree & Hierarchy** | `agent/python-agent/guardian/commands.py`<br>`apps/desktop-ui/js/apps-proc.js` | `cmd_pstree()`, `order(items)` |
| **Process Control & Signals** | `agent/python-agent/guardian/response.py` | `terminate_process()`, `suspend_process()`, `resume_process()`, `quarantine_file()` |
| **Critical Process Protection** | `agent/python-agent/guardian/response.py` | `PROTECTED_PROCESSES`, `is_protected()` |
| **Threads & Concurrency** | `agent/python-agent/guardian/agent.py`<br>`agent/python-agent/guardian/collectors/base.py` | `Agent.start()`, `Collector(threading.Thread)`, `thread_status()` |
| **Producer-Consumer Bounded Queue** | `agent/python-agent/guardian/queue.py` | `EventQueue`, `put()`, `drain()`, `_shed()` |
| **Synchronization & Condition Variables** | `agent/python-agent/guardian/queue.py`<br>`agent/python-agent/guardian/db.py` | `threading.Lock`, `threading.Condition`, `threading.RLock` |
| **Command Interpreter (Shell)** | `agent/python-agent/guardian/commands.py` | `split_line()`, `tokenize_shell()`, `execute_pipeline()`, `run()` |
| **Pipelines & I/O Redirection** | `agent/python-agent/guardian/commands.py` | `execute_pipeline()`, `_safe_shell_path()` |
| **Job Control (Background Jobs)** | `agent/python-agent/guardian/commands.py` | `JobManager`, `Job`, `cmd_jobs()`, `cmd_fg()`, `cmd_bg()`, `cmd_kill()` |
| **Inter-Process Communication (IPC)** | `agent/python-agent/guardian/api.py` | `create_app()`, `subscribers`, `asyncio.Queue`, `loop.call_soon_threadsafe()` |
| **File System & Storage Engine** | `agent/python-agent/guardian/db.py` | `Database`, WAL Mode (`PRAGMA journal_mode=WAL`), `migrate()` |
| **Crash & Corruption Recovery** | `agent/python-agent/guardian/db.py` | `_init_db()`, `recovery_notice`, timestamped isolation |
| **Static File & Metadata Analysis** | `agent/python-agent/guardian/pe.py` | `extract_metadata()`, `entropy()`, `mark_of_the_web()` |
| **Privilege & Access Control** | `agent/python-agent/guardian/capabilities.py`<br>`agent/python-agent/guardian/main.py` | `discover()`, `ctypes.windll.shell32.IsUserAnAdmin()`, per-session rotating token |
| **Tamper-Evident Hash-Chained Audit** | `agent/python-agent/guardian/db.py` | `Database.audit()`, `Database.verify_audit_chain()` |

---

## 1. Process Management & Process Hierarchy

### 1.1 Process Control Block (PCB) Sampling & Dual-Rate Diffing
* **File**: `agent/python-agent/guardian/collectors/processes.py`
* **Class**: `ProcessCollector(Collector)`
* **Mechanism**:
  - The OS maintains a Process Control Block (PCB) for every running process (PID, PPID, name, memory RSS, CPU times, start time).
  - High-frequency process spawning (e.g. short-lived dropper scripts) can be missed by slow polling. Guardian solves this with a **dual-rate scheduler**:
    1. **Fast Loop (`_tick_fast()`, every 0.5s)**: Queries `psutil.pids()`. By diffing `current_pids - known_pids`, newly spawned PIDs are detected with sub-second latency.
    2. **Full Loop (`_tick_full()`, every 2.0s)**: Full scan refreshing CPU, memory RSS, open handles, and parent relationships for all running processes.

### 1.2 PID Reuse Protection (Temporal Disambiguation)
* **File**: `agent/python-agent/guardian/collectors/processes.py`
* **Function**: `_make_pi(proc)`
* **Mechanism**:
  - Operating systems reuse Process IDs (PIDs) once a process terminates. A naive monitoring tool indexing by PID would confound an exited process with a new process assigned the same PID.
  - Guardian constructs a composite unique process key:
    $$\text{key} = \text{PID} : \text{int}(\text{start\_time})$$
  - If PID `1420` exits and a new process is assigned PID `1420` three seconds later, their start times differ, preventing telemetry collision.

### 1.3 Parent-Child Process Tree Hierarchy
* **Files**:
  - CLI: `agent/python-agent/guardian/commands.py` (`_cmd_pstree`)
  - GUI: `apps/desktop-ui/js/apps-proc.js` (`order(items)`)
* **Mechanism**:
  - In Unix and Windows, processes form an acyclic directed tree rooted at initial system processes (`system`, `init`, `smss.exe`).
  - `_cmd_pstree` builds an adjacency list `children[ppid] -> [pid]` and renders an ASCII tree (`├─`, `└─`, `│ `) displaying PID, PPID, and RSS.
  - `apps-proc.js` resolves parent relationships using `parent_key` with fallback to `ppid` against live PIDs, uses a `visited` set to guarantee cycle freedom, and displays child count badges `(N)`.

### 1.4 Real Process Control & Protection
* **File**: `agent/python-agent/guardian/response.py`
* **Functions**: `terminate_process()`, `suspend_process()`, `resume_process()`, `quarantine_file()`
* **Mechanism**:
  - **Termination**: Uses `psutil.Process(pid).terminate()` followed by `wait(timeout=3)`. Falls back to `kill()` if unresponsive.
  - **Suspension (SIGSTOP / NtSuspendProcess)**: `proc.suspend()` freezes process execution without terminating its memory space, enabling safe inspection.
  - **Resumption (SIGCONT / NtResumeProcess)**: `proc.resume()` restores the process to runnable state.
  - **Critical Process Guard (`is_protected()`)**: Refuses to terminate, suspend, or modify essential OS processes (`csrss.exe`, `lsass.exe`, `services.exe`, `smss.exe`, `wininit.exe`, `explorer.exe`, `system`, PID 0/4).

---

## 2. Threads, Concurrency & Multithreading Architecture

Guardian employs a multi-threaded architecture with thread lifecycle management, individual thread error counters, and heartbeat tracking.

### 2.1 Active Agent Thread Roster

| Thread Name | File / Location | Thread Role | Concurrency Primitive | Scheduling Model |
|---|---|---|---|---|
| `processes` | `guardian/collectors/processes.py` | Producer (Collector) | `threading.Thread` + `stop_flag.wait()` | Fast: 0.5s, Full: 2.0s |
| `resources` | `guardian/collectors/resources.py` | Producer (Collector) | `threading.Thread` + `stop_flag.wait()` | Periodic: 2.0s |
| `network` | `guardian/collectors/network.py` | Producer (Collector) | `threading.Thread` + `stop_flag.wait()` | Periodic: 2.0s |
| `windows_events` | `guardian/collectors/winevents.py` | Producer (Collector) | `threading.Thread` + `stop_flag.wait()` | EventLog polling: 2.0s |
| `registry_run_keys`| `guardian/collectors/registry.py` | Producer (Collector) | `threading.Thread` + `stop_flag.wait()` | Winreg polling: 5.0s |
| `writer` | `guardian/agent.py` | Consumer (DB Batch Writer) | `Condition Variable` (`drain()`) | Event-driven (batch drain) |
| `engine` | `guardian/agent.py` | Consumer (Correlation Engine) | `threading.Thread` + `stop_flag.wait()` | Periodic: 2.0s + retention: 1h |
| `enricher` | `guardian/enrich.py` | Worker (Hash / Authenticode) | `queue.Queue` (`Condition Variable`) | Event-driven worker pool |
| `heartbeat` | `guardian/agent.py` | Watchdog (System Liveness) | `threading.Thread` + `stop_flag.wait()` | Periodic: 5.0s |

### 2.2 Live Thread Telemetry Interface
* **File**: `agent/python-agent/guardian/agent.py`
* **Method**: `Agent.thread_status(self) -> list[dict]`
* **Export**: Exposed over the loopback REST API via `agent.health()["threads"]` and displayed in real time on the **`Active OS Agent Threads & Synchronization`** dashboard panel.

---

## 3. Synchronization & The Bounded Buffer (Producer-Consumer Problem)

### 3.1 Bounded Event Queue
* **File**: `agent/python-agent/guardian/queue.py`
* **Class**: `EventQueue`
* **OS Concept**: The classic **Producer-Consumer Problem** with a finite circular buffer. Multiple producer threads (collectors) append events, while the `writer` consumer thread drains batches into SQLite.

### 3.2 Concurrency Primitives
1. **Mutual Exclusion (`threading.Lock`)**:
   `self.lock` protects shared internal state (`collections.deque`, byte counter, dropped statistics).
2. **Condition Variables (`threading.Condition`)**:
   `self.not_empty` allows consumer threads to sleep without busy-waiting until producers insert items:
   ```python
   with self.not_empty:
       while not self.q and not self._closed:
           self.not_empty.wait(timeout=1.0)
   ```
3. **Re-entrant Locks (`threading.RLock`)**:
   Used in `guardian/db.py` (`self._lock`) to allow nested internal database transactions without deadlocks.

### 3.3 Backpressure & Priority-Based Load Shedding
* **Capacity Bounds**:
  - `QUEUE_MAX_EVENTS = 10,000`
  - `QUEUE_MAX_BYTES = 32 MB`
* **Thresholds**:
  - **Warning (70% fill)**: System marks queue state as `"warning"`.
  - **Shedding (90% fill)**: Initiates priority load shedding.
* **Priority Queue Shedding Strategy**:
  When the queue exceeds the shedding ratio, `_shed()` drops lower-priority events first:
  $$\text{Priority 0 (Never shed)}: \text{alert}, \text{sensor\_tamper}$$
  $$\text{Priority 1}: \text{process\_start}, \text{persistence\_change}, \text{defender\_detection}$$
  $$\text{Priority 2}: \text{process\_end}, \text{network\_connect}, \text{windows\_event}$$
  $$\text{Priority 5 (Shed first)}: \text{image\_load}$$

---

## 4. Guardian Shell (Command Interpreter & Job Control)

* **File**: `agent/python-agent/guardian/commands.py`

### 4.1 Lexical Parsing & Tokenization
- `tokenize_shell(line: str) -> list[str]`:
  Recognizes shell control operators (`|`, `>`, `>>`, `<`, `&`) while preserving double-quoted (`"..."`) and single-quoted (`'...'`) strings and Windows file path backslashes.

### 4.2 Pipelines (`|`)
- Standard UNIX pipeline semantics implemented in userspace:
  $$\text{Stage}_1 \xrightarrow{\text{stdout } \to \text{ stdin}} \text{Stage}_2 \xrightarrow{\text{stdout } \to \text{ stdin}} \text{Stage}_3$$
- Example: `processes --top 15 | grep python | wc`

### 4.3 Sandboxed File Redirection (`>`, `>>`, `<`)
- Output redirection writes (`>`) or appends (`>>`) stdout to files. Input redirection (`<`) supplies stdin from a file.
- **Path Traversal Defense (`_safe_shell_path`)**:
  All redirection targets are strictly locked to `config.data_dir() / "shell"`. Attempts to escape via `../` or absolute system paths (`C:\Windows\...`) raise a sandboxing permission exception.

### 4.4 Background Job Control
- **Class**: `JobManager` & `Job`
- **Background Operator (`&`)**: Commands ending with `&` (e.g. `sleep 10 &`) spawn a background daemon thread tracked with an incrementing Job ID (`[1]`, `[2]`).
- **State Machine**: Tracks states `running`, `stopped`, `done`, `terminated`, along with elapsed time and captured stdout.
- **Shell Job Builtins**:
  - `jobs`: Lists active and finished jobs.
  - `fg <id>`: Brings a background job to foreground, waits for completion (`thread.join()`), and prints output.
  - `bg <id>`: Resumes a stopped job in background.
  - `kill <id>`: Sends a termination signal via `cancel_event` to abort the job immediately.

---

## 5. Inter-Process Communication (IPC)

### 5.1 Loopback REST API & WebSocket Event Streaming
* **File**: `agent/python-agent/guardian/api.py`
* **Mechanism**:
  - The UI (desktop frontend) runs in a separate process from the agent engine.
  - They communicate via HTTP REST endpoints and persistent WebSockets on `127.0.0.1`.
  - Thread-to-Asyncio Bridge: Background threads notify async WebSocket clients using `loop.call_soon_threadsafe()` into an `asyncio.Queue`.

### 5.2 OS Subprocess & Utility Pipes
* **Files**:
  - `agent/python-agent/guardian/enrich.py`: PowerShell pipe for Authenticode signature extraction (`powershell -NoProfile -Command Get-AuthenticodeSignature`).
  - `agent/python-agent/guardian/collectors/winevents.py`: Interacts with `wevtutil` for Windows Event Log bookmarking.
  - `agent/python-agent/guardian/response.py`: Uses `icacls` via subprocess to strip read/write permissions on quarantined files.

---

## 6. File System, Storage Engine & Crash Recovery

### 6.1 SQLite Write-Ahead Logging (WAL) Mode
* **File**: `agent/python-agent/guardian/db.py`
* **Pragmas**:
  - `PRAGMA journal_mode = WAL;` — Enables concurrent readers while a single writer thread commits batches.
  - `PRAGMA synchronous = NORMAL;` — Maximizes write throughput while preventing corrupt transactions across power failures.
  - `PRAGMA busy_timeout = 5000;` — Handles concurrent file locking gracefully.

### 6.2 Atomic Schema Migrations
* **File**: `agent/python-agent/guardian/db.py` (`migrate()`)
* **Mechanism**: Database schemas are versioned with sequential `.sql` migration files applied atomically inside SQLite transactions.

### 6.3 Automatic Database Corruption Recovery
* **File**: `agent/python-agent/guardian/db.py` (`_init_db()`)
* **Mechanism**:
  - If a crash corrupts the SQLite header, Guardian catches `sqlite3.DatabaseError`.
  - The damaged database file is safely quarantined as `db.corrupt-<timestamp>.db` for forensic analysis.
  - A fresh database is initialized and a `db_recovered` audit event is emitted.

### 6.4 Static File Intelligence & NTFS Metadata
* **File**: `agent/python-agent/guardian/pe.py`
* **Mechanisms**:
  - **Shannon Entropy (`entropy()`)**: Calculates bitwise uncertainty ($H = -\sum p \log_2 p$) across PE sections. Entropy $> 7.2$ flags packed or encrypted code.
  - **NTFS Alternate Data Streams (`mark_of_the_web()`)**: Reads `:Zone.Identifier` stream attached by Windows to downloaded binaries to ascertain file provenance (`ZoneId=3` for Internet).

### 6.5 Windows Registry & OS Persistence Architecture
* **File**: `agent/python-agent/guardian/collectors/registry.py`
* **Class**: `RegistryCollector`
* **Mechanism**:
  - The Windows Registry is a hierarchical kernel configuration and persistence database.
  - `RegistryCollector` interfaces with Python's low-level `winreg` C-binding to inspect auto-start extension points:
    - `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
    - `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
  - Periodically snapshots registry entries and performs dictionary state diffing. Any unauthorized creation, modification, or deletion generates a `persistence_change` telemetry event (Priority 1) pushed directly into the `EventQueue`.

---

## 7. Security, Privilege & Auditing

### 7.1 Least Privilege & Administrator Capability Discovery
* **File**: `agent/python-agent/guardian/capabilities.py`
* **Function**: `discover()`
* **Mechanism**:
  - Evaluates privileges using `ctypes.windll.shell32.IsUserAnAdmin()`.
  - Runs safely in non-elevated user mode. If administrator privileges are missing, Security Event Log reading degrades gracefully without crashing the core agent.

### 7.2 Per-Session Token & Loopback Isolation
* **File**: `agent/python-agent/guardian/main.py`
* **Mechanism**:
  - Every agent startup generates a cryptographically secure 256-bit token (`secrets.token_urlsafe(32)`).
  - All REST and WebSocket endpoints require this token via the `X-Guardian-Token` header, defending against Cross-Site Request Forgery (CSRF) or unauthorized local processes.

### 7.3 Tamper-Evident SHA-256 Hash-Chained Audit Log
* **File**: `agent/python-agent/guardian/db.py`
* **Methods**: `Database.audit()`, `Database.verify_audit_chain()`
* **Mechanism**:
  - Every critical action (acknowledge, dismiss, terminate, quarantine) writes to the `audit_log` table.
  - Each entry incorporates the SHA-256 digest of the previous entry:
    $$\text{Hash}_k = \text{SHA-256}(\text{Hash}_{k-1} \parallel \text{timestamp} \parallel \text{action} \parallel \text{target} \parallel \text{actor})$$
  - `verify_audit_chain()` walks the table verifying every link in $O(N)$ time. If an attacker directly alters a row in SQLite, the cryptographic chain is broken immediately.

---

## Summary for Viva Defense

When explaining this project to an OS instructor, summarize the architecture as:
1. **Multithreaded Producer-Consumer Engine**: Asynchronous I/O sensor threads feeding a bounded condition-variable queue with load shedding.
2. **Userspace Process & Concurrency Monitor**: Sub-second process diffing with PID reuse protection, parent-child tree mapping, and signals.
3. **Userspace Command Shell**: Custom lexical analyzer supporting pipelines, sandboxed redirection, and background job scheduling.
4. **Crash-Resilient Storage**: WAL-mode SQLite database with automatic corruption isolation and cryptographic tamper-evident audit logging.
