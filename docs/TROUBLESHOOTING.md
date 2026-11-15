# Guardian OS — Troubleshooting & Diagnostics Guide

---

## 1. Common Operational Scenarios

### 1.1 "Limited Protection • Needs Admin Access" Status Pill
- **Cause**: Guardian OS was launched as a standard non-elevated user via `run.bat`. Windows limits access to the Security Event Log (`EventID 1102`) and elevated process paths to Administrator accounts.
- **Remedy**: Close the window and run `run_admin.bat` to elevate privileges with Windows UAC.

### 1.2 Command Palette Shortcut (`Ctrl+K` or `ESC`)
- **Behavior**: Pressing `ESC` anywhere on the desktop immediately dismisses the active Command Palette or closes the topmost focused floating window (Terminal, Processes, etc.).
- **Force Reset**: Click the `ESC` badge or `×` close icon located at the right edge of the search box.

### 1.3 Port Conflict (`Address already in use`)
- **Cause**: Another Guardian instance or process is listening on port `8765`.
- **Remedy**: Pass a custom port flag to the launcher:
  ```cmd
  python -m guardian.main --port 8766
  ```

### 1.4 Database Corruption Recovery
- **Built-in Self-Healing**: If a power loss or unexpected shutdown damages the SQLite database, Guardian OS automatically detects the corrupt header, renames the damaged file to `guardian.corrupt-<timestamp>.db`, initializes a clean database, and logs an alert.
- **Manual Verification**: Run `check.bat` to perform an automated health self-check.

### 1.5 WebSocket Disconnection & Reconnection
- **Behavior**: If the Python daemon restarts, the UI displays a subtle reconnecting indicator. The desktop shell automatically polls `/api/v1/auth/session` on loopback and re-establishes the WebSocket connection within 3 seconds without losing UI state.
