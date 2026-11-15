# Guardian OS — Architecture & Concurrency Review
**Date**: November 15, 2026  
**Focus**: Multi-threaded Producer-Consumer Pipeline, Thread Synchronization, IPC, and State Management  

---

## 1. Concurrency Architecture Diagram

```
[ Collector: Resources ]     (Thread, T=2.0s)  ──┐
[ Collector: Processes ]     (Thread, T=0.5s)  ──┼──> [ Normalise & Redact ]
[ Collector: Network ]       (Thread, T=3.0s)  ──┤         │
[ Collector: WinEvents ]     (Thread, T=10.0s) ──┤         ▼
[ Collector: Registry ]      (Thread, T=10.0s) ──┘   [ EventQueue (Bounded) ]
                                                            │
                                              threading.Condition (not_empty)
                                                            │
                                  ┌─────────────────────────┴────────────────────────┐
                                  ▼                                                  ▼
                        [ DB Batch Writer ]                                 [ Correlation Engine ]
                     (Single consumer thread)                              (Thread, periodic sweep)
                                  │                                                  │
                                  ▼                                                  ▼
                         SQLite WAL Storage                                   Incident Detections
                                  │                                                  │
                                  └────────────────────────┬─────────────────────────┘
                                                           ▼
                                                [ FastAPI / WebSockets ]
                                                           │
                                                           ▼
                                                [ Desktop UI Frontend ]
```

---

## 2. Synchronization Primitives Analysis

### 2.1 The Bounded Queue (`guardian/queue.py`)
- **Mutex**: `self.lock = threading.Lock()` guarantees exclusive access to the underlying `collections.deque` and metric counters (`dropped`, `generated`).
- **Condition Variable**: `self.not_empty = threading.Condition(self.lock)` implements blocking consumer waits with timeouts:
  ```python
  with self.not_empty:
      while not self.queue and not stop_event.is_set():
          self.not_empty.wait(timeout=1.0)
  ```
- **Load Shedding**: When `len(self.queue) >= self.max_size` (10,000 items) or estimated memory exceeds 32 MB, the queue sheds events based on priority:
  - Severity `critical` / `high` (Priority 0) are protected.
  - Periodic CPU/disk heartbeat metrics (Priority 5) are pruned first.

### 2.2 Thread Lifecycle & Heartbeat Watchdog (`guardian/agent.py`)
- **Worker Threads**:
  - `writer`: Drains the queue in micro-batches (up to 200 items or 0.2s elapsed) inside atomic SQLite transactions.
  - `enricher`: Background thread performing Shannon entropy calculation and Authenticode verification on unknown binaries without stalling process collectors.
  - `engine`: Runs detection rules and merges multi-stage incidents within the `join_window_seconds` (120s) and `incident_merge_window_seconds` (600s).
  - `heartbeat`: Periodically checks that all collector threads have updated their `last_tick` timestamp within 3x their scheduled interval.
- **Graceful Shutdown**:
  - `Agent.stop()` sets stop events, wakes up condition variables via `notify_all()`, and joins threads with a bounded timeout (2.0s).

---

## 3. IPC & Frontend Communication (`guardian/api.py`)
- **Inter-Process Boundary**: The backend agent runs as a standalone Python process; the UI runs inside Microsoft Edge in `--app` mode (or standard Chromium browser).
- **Security Envelope**:
  - Bound strictly to `127.0.0.1` loopback.
  - Rejects external Host headers (DNS rebinding protection).
  - Authenticated via session tokens rotated at each agent startup.
- **WebSocket Broadcast**:
  - Collector anomalies, system metric updates, and newly opened incidents are pushed over `ws://127.0.0.1:<port>/api/v1/ws`.
  - Avoids aggressive client-side polling while maintaining live sub-second UI responsiveness.
