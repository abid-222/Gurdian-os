# Guardian OS — Phase 1 Bug Fix Report
**Date**: November 15, 2026  
**Status**: Completed & Verified  

---

## 1. Summary of Defects & Applied Fixes

### Bug 1: Lingering SQLite WAL Logs on Clean Shutdown
- **Root Cause**: `Database` class lacked an explicit clean closing method with WAL truncation pragma.
- **Fix**: Added `Database.close()` executing `PRAGMA wal_checkpoint(TRUNCATE)` before closing the connection.
- **Affected File**: `agent/python-agent/guardian/db.py`
- **Verification**: `test_agent_graceful_stop_and_wal_truncation` passed.

### Bug 2: Thread Leaks & Ungraceful Agent Termination
- **Root Cause**: `Agent.stop()` only signaled `stop_flag.set()` but did not wake up threads blocked on `EventQueue.cv` nor join collector/worker threads.
- **Fix**: Updated `Agent.stop()` to notify condition variables, join all collectors, the enricher thread, and core worker threads with bounded 1.0s timeouts, followed by `db.close()`.
- **Affected File**: `agent/python-agent/guardian/agent.py`
- **Verification**: Clean agent cycle tests confirmed 0 thread leaks.

### Bug 3: Potential Negative Byte Calculation in Bounded Queue
- **Root Cause**: In `EventQueue.drain()`, decrementing `self.bytes -= size` could theoretically underflow if inconsistent sizes were popped.
- **Fix**: Clamped byte counter via `self.bytes = max(0, self.bytes - size)`.
- **Affected File**: `agent/python-agent/guardian/queue.py`
- **Verification**: `test_queue_backpressure_and_shedding` passed.
