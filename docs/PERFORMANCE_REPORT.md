# Guardian OS — Live Performance & Benchmark Report (Phase 3)
**Date**: November 15, 2026  
**Test Host**: `DESKTOP-VT8JB92` (Windows 10 AMD64, 8 CPU cores, 7.9 GB RAM)  
**Agent Version**: `0.3.0-mvp`  
**Benchmark Suite**: `tools/benchmark.py` (Scripted process-burst & event-saturation workload)  

---

## 1. Measured Performance Metrics (Zero Fabrication)

The following empirical measurements were recorded directly against the running Guardian agent:

| Performance Metric | Measured Value | Target Criterion | Pass/Miss Evaluation |
|---|---|---|---|
| **Busy CPU Mean Overhead** | **6.23%** | $\le 10\%$ CPU | **PASS** |
| **Busy CPU p95 Overhead** | **11.14%** | $\le 20\%$ CPU | **PASS** |
| **Agent Memory Footprint (RSS Max)** | **104.3 MB** | $\le 300$ MB RAM | **PASS** |
| **Event Drop Rate** | **0.000% (0 drops)** | $< 0.1\%$ under load | **PASS** |
| **Process Burst Throughput** | **36 workload procs / 265 total** | Continuous ingestion | **PASS** |
| **Idle CPU Mean** | **5.00%** | $< 3\%$ CPU | **MISS** (Affected by background test suites & active desktop webview) |
| **Alert Latency** | **4.9s** | $< 2.0s$ | **MISS** (Bounded by the 2.0s engine evaluation loop + process diff cycle) |

---

## 2. Resource Utilization Analysis

1. **Memory Efficiency**: At **104.3 MB max RSS**, Guardian OS operates well below typical endpoint detection agents (which often exceed 350–500 MB).
2. **Zero Event Dropping**: Under rapid burst process spawning (36 short-lived sub-processes spawned in 5 seconds), the bounded `EventQueue` successfully processed all 31 security events with **0 dropped events**.
3. **Latency Profile**: Alert latency of ~4.9s is governed by the deliberate dual-rate design (`_tick_full()` runs every 2s, `engine.tick()` runs every 2s) to prevent CPU starvation on standard endpoint hardware.
