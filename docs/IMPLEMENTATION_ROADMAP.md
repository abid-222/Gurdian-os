# Guardian OS — Implementation Roadmap
**Date**: November 15, 2026  
**Status**: Ready for Principal Review & Approval  

This document details prioritized engineering tasks to elevate Guardian OS from an advanced laboratory prototype to an enterprise-grade academic showcase.

---

## Roadmap Matrix

| ID | Priority | Module / Area | Problem Description | Proposed Solution | Risk | Dependencies | Acceptance Criteria | Tests Required |
|---|---|---|---|---|---|---|---|---|
| **R1** | **P0 (Critical)** | `apps/desktop-ui/js/apps-proc.js` | Process termination & quarantine rely on browser `window.prompt()` which freezes Chromium app rendering. | Implement custom framed glassmorphic Confirmation Modal inside UI. | Low | `apps-proc.js`, `shell.css` | Process name confirmation requested in non-blocking glass dialog. | E2E Action dialog test |
| **R2** | **P1 (High)** | `guardian/queue.py` | `sys.getsizeof` shallow calculation under-estimates event dictionary memory usage. | Implement recursive or heuristic memory estimator for event payloads. | Low | `queue.py` | Accurate RAM tracking in queue status (<5% deviation). | `test_queue_memory_bounds` |
| **R3** | **P1 (High)** | `guardian/db.py` | No automated WAL checkpoint/vacuum during agent clean shutdown. | Add explicit `PRAGMA wal_checkpoint(TRUNCATE)` on `Database.close()`. | Low | `db.py` | WAL file truncated cleanly to zero bytes upon `agent.stop()`. | `test_clean_wal_checkpoint` |
| **R4** | **P2 (Medium)** | `deployment/installer/install_sysmon.ps1` | Sysmon downloaded over web without pinned SHA-256 hash fallback (only Authenticode). | Add pinned SHA-256 checksum validation for official Sysinternals release. | Low | `install_sysmon.ps1` | Installation halts with clear error if hash mismatch occurs. | Script verification |
| **R5** | **P2 (Medium)** | `optional/ai/malware-pe/` | 4 tests skipped due to missing synthetic training artifacts in fresh clone. | Add a lightweight synthetic dataset fixture generator for fast unit testing. | Medium | `test_v02.py`, `trainer.py` | All 36 pytest tests pass (`36 passed, 0 skipped`). | `pytest tests` |
| **R6** | **P3 (Enhance)** | `apps/desktop-ui/js/apps-sec.js` | Incident notes author defaults to hardcoded "analyst" rather than host user. | Pull authenticated OS username from `document.body.dataset.host` / user info. | Low | `apps-sec.js`, `api.py` | Incident notes reflect actual system user logged into Guardian. | Note audit verification |

---

## Recommended Execution Order

1. **Phase 1: Zero-Freeze Frontend Dialogs (R1)**: Eliminate native browser `prompt()` blocking in Process Center.
2. **Phase 2: Data Integrity & Storage Hardening (R2, R3)**: Accurate queue RAM accounting and clean WAL checkpointing.
3. **Phase 3: Installer & Deployment Security (R4)**: Sysmon pinned hash integrity.
4. **Phase 4: Test Suite Completeness (R5)**: Synthetic ML fixtures ensuring 36/36 tests pass out-of-the-box.
5. **Phase 5: User Experience & Polish (R6)**: Live username attribution for forensic incident notes.
