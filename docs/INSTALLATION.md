# Guardian OS — Installation Guide (v1.0 Release)

This document provides complete instructions for installing, configuring, running, and uninstalling Guardian OS on Windows 10 and 11.

---

## 1. Prerequisites

- **Operating System**: Windows 10 or 11 (64-bit AMD64 recommended)
- **Python**: Version 3.10, 3.11, or 3.12 (must be added to `PATH`)
- **Privileges**: Standard user works out-of-the-box (degraded Security Log); Administrator recommended for full telemetry (`run_admin.bat`).
- **Network**: 100% offline self-contained (no external internet required for runtime).

---

## 2. One-Time Installation

Run the automatic installer script from the root repository folder:
```cmd
install.bat
```
This script performs:
1. Verifies Python 3.10+ installation.
2. Creates an isolated local virtual environment in `.venv`.
3. Upgrades pip and installs core dependencies from `requirements.txt`.
4. Installs test harnesses (`pytest`, `httpx`).
5. Runs the automated verification suite to guarantee machine compatibility.

---

## 3. Running Guardian OS

### Standard User Mode
```cmd
run.bat
```
Starts the Python backend daemon on a loopback port (default `8765`), generates a 256-bit cryptographic session token, and opens the framed desktop workstation in Microsoft Edge `--app` mode.

### Elevated Administrator Mode (Recommended for Full Telemetry)
```cmd
run_admin.bat
```
Launches Guardian OS with elevated UAC permissions, enabling Windows Security Event Log reading and deep process handle inspection.

---

## 4. Optional Components

### Automatic User Logon Startup
To automatically launch Guardian OS in the background when your Windows user signs in:
```cmd
autostart_install.bat
```
*(Registers a scheduled task under `RunLevel Limited`, no admin prompt required at login).*

### Deep Sysmon Telemetry (Optional)
To enable kernel-level file-creation and DNS telemetry via Microsoft Sysmon:
```powershell
powershell -ExecutionPolicy Bypass -File deployment\installer\install_sysmon.ps1
```

---

## 5. Uninstallation & Data Management

To remove the autostart logon task:
```cmd
uninstall.bat
```

To remove the autostart task and completely purge all local databases, quarantine stores, and virtual environments:
```cmd
uninstall.bat purge
```
