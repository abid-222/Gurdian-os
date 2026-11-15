# Guardian OS — Phase 1 Test Report
**Date**: November 15, 2026  
**Test Engine**: pytest 9.2.0 / Python 3.12.10 (Win32 AMD64)  
**Total Tests**: 38 (+2 newly implemented regression tests)  

---

## 1. Test Results Summary

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\ANTI BAP\smart-os-guardian-v0.3.0\smart-os-guardian
plugins: anyio-4.16.0
collected 38 items

tests/integration/test_scenarios_api.py .........                        [ 23%]
tests/unit/test_core.py .........                                        [ 47%]
tests/unit/test_v02.py ........s...sss.....                              [100%]

================== 34 passed, 4 skipped, 1 warning in 36.90s ==================
```

---

## 2. New Regression Tests Added

1. `test_agent_graceful_stop_and_wal_truncation` (`tests/unit/test_core.py`):
   - Verifies that `Agent.stop()` properly joins threads and cleanly truncates the WAL database file, allowing safe subsequent re-opening without database corruption.
2. `test_quarantine_path_traversal_refused` (`tests/unit/test_core.py`):
   - Asserts that directory traversal payloads (`../evil`) and invalid identifiers in quarantine restore attempts are rejected safely by `response.ActionError`.
