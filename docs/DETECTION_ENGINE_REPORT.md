# Guardian OS — Detection Engine Report (Phase 3)
**Date**: November 15, 2026  
**Auditor / Architect**: Principal Security Engineer & Autonomous Lead  
**Scope**: Threat Detection Pipeline, Evidence Classes E1–E6, Lineage Correlation, and Alert Explainability  

---

## 1. Detection Architecture & Evidence Classes

Guardian OS implements a multi-stage, explainable incident generation framework based on six orthogonal evidence classes:

| Class | Evidence Category | Detection Rule | Weight | Primary Trigger & Source |
|---|---|---|---|---|
| **E1** | Calibrated PE ML Score | `M-PE-LGBM` | 3 (Strong) | Validated LightGBM static feature score $\ge$ validation threshold. Degrades gracefully to rules-only when uninstalled. |
| **E2** | Anomalous Parent-Child Lineage | `R-PARENT-CHILD` | 2 (Medium) | Office applications (`winword.exe`, `excel.exe`) or script hosts (`wscript.exe`, `mshta.exe`) spawning shell interpreters (`cmd.exe`, `powershell.exe`) or unsigned binaries. |
| **E3** | Drop-and-Execute | `R-DROP-EXEC` | 2 (Medium) | Executable created in a user-writable path (`\AppData\`, `\Temp\`, `\Downloads\`) and executed within 60 seconds of file creation. |
| **E4** | Untrusted Path & Signer Context | `R-UNSIGNED-WRITABLE` | 1 (Weak) | Unsigned/invalid Authenticode binary executed from outside trusted OS roots (`C:\Windows\`, `C:\Program Files\`). |
| **E5** | Persistence Alteration | `R-PERSIST-RUNKEY` | 2 (Medium) | Registry Run/RunOnce key modification attributed via Sysmon Events 12–14 or Registry collector. |
| **E6** | Rapid Early Outbound Network Flow | `R-EARLY-OUTBOUND` | 1 (Weak) | Non-OS binary establishing an external public IP socket connection within 120 seconds of process creation. |

---

## 2. Multi-Stage Temporal Correlation

- **Join Key**: Processes are linked across collectors using the unique temporal composite key `process_key = f"{pid}:{int(create_time * 1000)}"`, eliminating PID-reuse ambiguity.
- **Incident Merging Window**:
  - Detections sharing the same parent-child ancestry or identical binary SHA-256 hash are unified within `incident_merge_window_seconds = 600s`.
  - Merged incidents prevent alert fatigue by generating a single compound incident with chronological evidence steps.
- **Noise Suppression**:
  - `medium_requires_non_weak = True`: Two weak signals alone (e.g. E4 + E6) stay classified as Informational timeline entries rather than firing high-urgency alerts.

---

## 3. Explainable Alert Structure

Every incident reported by Guardian OS provides concrete answers to the 6 core operator questions:
1. **What happened?**: Clear incident summary showing the causal progression of actions.
2. **Which process was involved?**: Exact executable name, PID, parent PID, command line (redacted for secrets), and file creation timestamp.
3. **What evidence was found?**: List of triggered evidence classes (E1–E6) with rule IDs and reference indicators.
4. **Why is it suspicious?**: Plain-language risk explanation detailing why this behavioral sequence violates the security baseline.
5. **What is the severity?**: Calibrated classification (`informational`, `low`, `medium`, `high`, `critical`) derived from aggregate evidence weight.
6. **What should the user do?**: Actionable investigation steps (e.g. check parent process origin, inspect remote IP in Network Center, allowlist hash).
