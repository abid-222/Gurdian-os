# Guardian OS — Release Notes (v1.0.0)
**Release Date**: November 15, 2026  
**Milestone**: v1.0.0 General Availability & Academic Showcase  

---

## What's New in Guardian OS v1.0.0

### 1. Modern Framed Desktop Security Workstation
- Completely redesigned from terminal monospace text into a modern, macOS Sequoia / Linear style **Framed Glassmorphic Bento Grid**.
- **9 Core Application Modules**: Overview Dashboard, Process Explorer, Thread & Concurrency Monitor, Security Center, Network Monitor, File Intelligence, Guardian Terminal, Audit & Recovery, and Settings.
- **Squircle Vector Icon System**: 3D glassmorphic squircle icon frames with semantic color coding (`cyan`, `emerald`, `amber`, `rose`, `indigo`, `purple`, `slate`).
- **Non-Blocking Action Modals**: Replaced legacy browser prompts with custom glassmorphic confirmation dialogs (`confirmDialog`) for terminating/quarantining processes and allowlisting.
- **Universal ESC Handling**: Pressing `ESC` anywhere on the screen closes the topmost open window or Command Palette without trapped states.

### 2. Operating System Concepts & Concurrency Engine
- **Dual-Rate Process PCB Diffing**: 0.5s fast loop catches transient dropper processes; 2.0s deep scan maintains CPU and memory trends.
- **PID-Reuse Collision Shield**: Assigns unique temporal keys (`pid:create_time`) to all process entities.
- **Bounded Producer-Consumer Queue**: Capacity-bounded (10,000 events) synchronized buffer with condition variables and priority load shedding.
- **Live Thread Telemetry**: In-depth monitoring of 9+ internal collector and worker threads with real-time heartbeat tracking.
- **Tamper-Evident SHA-256 Audit Chain**: Append-only cryptographic ledger of all user and administrative actions.

### 3. Detection Engine & Explainable Incidents
- Evidence classes **E1–E6** with temporal union-find clustering across 600-second correlation windows.
- Compound multi-stage incidents answering: What happened, Which process was involved, What evidence was discovered, Why it is suspicious, Severity rating, and Recommended mitigation steps.

### 4. Reliability & Deployment
- One-click installer script (`install.bat`) with isolated virtual environment setup.
- Windows Scheduled Task logon autostart (`autostart_install.bat`) running without administrator requirements.
- Clean SQLite WAL shutdown with automatic log truncation (`wal_checkpoint(TRUNCATE)`).
