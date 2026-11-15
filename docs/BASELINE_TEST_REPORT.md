# Guardian OS — Baseline Test Report
**Date**: November 15, 2026  
**Environment**: Windows 10 AMD64 / Python 3.12.10 / pytest 9.2.0  
**Test Suite**: Unit, Integration, and OS Lab Scenarios  

---

## 1. Automated Test Execution Summary

```
============================= test session starts =============================
platform win32 -- Python 3.12.10, pytest-9.2.0, pluggy-1.7.0
rootdir: D:\ANTI BAP\smart-os-guardian-v0.3.0\smart-os-guardian
plugins: anyio-4.16.0
collected 36 items

tests/integration/test_scenarios_api.py::test_drop_and_execute_one_linked_incident PASSED [  2%]
tests/integration/test_scenarios_api.py::test_benign_scenario_stays_quiet PASSED [  5%]
tests/integration/test_scenarios_api.py::test_log_cleared_observation PASSED [  8%]
tests/integration/test_scenarios_api.py::test_allowlist_suppresses PASSED [ 11%]
tests/integration/test_scenarios_api.py::test_api_auth_host_origin PASSED [ 13%]
tests/integration/test_scenarios_api.py::test_api_actions_preview_is_harmless_and_execute_is_guarded PASSED [ 16%]
tests/integration/test_scenarios_api.py::test_api_input_validation PASSED [ 19%]
tests/integration/test_scenarios_api.py::test_terminal_and_scan PASSED   [ 22%]
tests/integration/test_scenarios_api.py::test_ack_and_dismiss_audited PASSED [ 25%]
tests/unit/test_core.py::test_redaction PASSED                           [ 27%]
tests/unit/test_core.py::test_event_envelope PASSED                      [ 30%]
tests/unit/test_core.py::test_queue_backpressure_and_shedding PASSED     [ 33%]
tests/unit/test_core.py::test_severity_policy PASSED                     [ 36%]
tests/unit/test_core.py::test_sysmon_fixture_parsing_and_mapping PASSED  [ 38%]
tests/unit/test_core.py::test_audit_chain PASSED                         [ 41%]
tests/unit/test_core.py::test_migration_and_wal PASSED                   [ 44%]
tests/unit/test_v02.py::test_terminal_strips_quotes_keeps_backslashes PASSED [ 47%]
tests/unit/test_v02.py::test_eventlog_bookmark_no_loss_no_duplicates PASSED [ 50%]
tests/unit/test_v02.py::test_db_recovers_from_corruption PASSED          [ 52%]
tests/unit/test_v02.py::test_retention_uses_user_setting PASSED          [ 55%]
tests/unit/test_v02.py::test_e1_uses_model_threshold_not_policy_constant PASSED [ 58%]
tests/unit/test_v02.py::test_unvalidated_model_is_not_evidence PASSED    [ 61%]
tests/unit/test_v02.py::test_incident_keeps_process_name_after_exit PASSED [ 63%]
tests/unit/test_v02.py::test_notes_export_hash_search_and_live_privacy PASSED [ 66%]
tests/unit/test_v02.py::test_pe_pipeline_train_package_load_score SKIPPED [ 69%]
tests/unit/test_v02.py::test_response_terminate_needs_typed_confirmation PASSED [ 72%]
tests/unit/test_v02.py::test_response_refuses_protected_and_self PASSED  [ 75%]
tests/unit/test_v02.py::test_response_quarantine_and_restore PASSED      [ 77%]
tests/unit/test_v02.py::test_dataset_scan_unpacks_zip_and_reads_csv SKIPPED [ 80%]
tests/unit/test_v02.py::test_csv_training_end_to_end_with_quality_gate SKIPPED [ 83%]
tests/unit/test_v02.py::test_hot_reload_picks_up_new_model SKIPPED [ 86%]
tests/unit/test_v02.py::test_guardian_shell_pipeline PASSED              [ 88%]
tests/unit/test_v02.py::test_guardian_shell_redirection PASSED           [ 91%]
tests/unit/test_v02.py::test_guardian_shell_background_job_control PASSED [ 94%]
tests/unit/test_v02.py::test_guardian_shell_os_inspection_and_security PASSED [ 97%]
tests/unit/test_v02.py::test_agent_thread_status_and_health PASSED       [100%]

================== 32 passed, 4 skipped, 1 warning in 20.95s ==================
```

---

## 2. Test Coverage by Subsystem

| Test Module | Tests | Passing | Skipped | Failing | Focus Area |
|---|---|---|---|---|---|
| `test_scenarios_api.py` | 9 | 9 | 0 | 0 | API authentication, scenarios (drop & execute, benign, log clear), allowlist |
| `test_core.py` | 7 | 7 | 0 | 0 | Token redaction, event schema, queue backpressure, audit hash chain, WAL |
| `test_v02.py` | 20 | 16 | 4 | 0 | Shell pipes, jobs, DB recovery, bookmarks, guarded responses, threads |

---

## 3. Analysis of Skipped Tests

The 4 skipped tests in `test_v02.py` correspond to the optional `malware-pe` ML pipeline:
- `test_pe_pipeline_train_package_load_score`: Requires trained model artifact.
- `test_dataset_scan_unpacks_zip_and_reads_csv`: Requires extracted CSV in `optional/datasets/csv`.
- `test_csv_training_end_to_end_with_quality_gate`: Requires `lightgbm` and `scikit-learn`.
- `test_hot_reload_picks_up_new_model`: Requires running trainer daemon.

**Verdict**: All core OS and agent capabilities have 100% test pass rate. The optional ML slot degrades gracefully to rules-only (E2–E6) as intended by architectural design.
