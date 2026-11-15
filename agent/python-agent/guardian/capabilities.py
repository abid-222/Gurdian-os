"""Capability discovery (spec step 2): unsupported sources are marked unavailable, never silently empty."""
from __future__ import annotations
import platform, subprocess, shutil, os, sys
from . import config

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def is_admin() -> bool:
    if config.IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _wevtutil_ok(channel: str) -> tuple[bool, str]:
    try:
        r = subprocess.run(["wevtutil", "qe", channel, "/c:1", "/f:xml"], capture_output=True, text=True, timeout=10,
                           creationflags=0x08000000)
        if r.returncode == 0:
            return True, ""
        msg = (r.stderr or r.stdout or "").strip().splitlines()
        return False, (msg[0] if msg else f"exit {r.returncode}")
    except Exception as e:
        return False, str(e)


def sysmon_service() -> str | None:
    if not (config.IS_WINDOWS and psutil):
        return None
    for name in ("Sysmon64", "Sysmon"):
        try:
            return f"{name}:{psutil.win_service_get(name).status()}"
        except Exception:
            continue
    return None


def discover(model_loaded: bool = False, pe_parser: bool = False) -> dict:
    admin = is_admin()
    caps = {}

    def put(name, status, reason="", **extra):
        caps[name] = {"status": status, "reason": reason, **extra}

    put("processes", "available" if psutil else "unavailable", "psutil" if psutil else "psutil not installed")
    put("network", "available" if psutil else "unavailable",
        "psutil connection table" + ("" if admin else " (non-elevated: some PIDs hidden)"))
    put("resources", "available" if psutil else "unavailable")
    if config.IS_WINDOWS and shutil.which("wevtutil"):
        ok, why = _wevtutil_ok("System")
        put("event_log_system", "available" if ok else "unavailable", why)
        ok, why = _wevtutil_ok("Security")
        put("event_log_security", "available" if ok else "degraded",
            "" if ok else f"needs admin / Event Log Readers ({why}); log-clear 1102 not observable")
        svc = sysmon_service()
        if svc is None:
            put("sysmon", "unavailable", "Sysmon is not installed (optional). File-create, registry and DNS telemetry limited.")
        elif svc.endswith("running"):
            ok, why = _wevtutil_ok("Microsoft-Windows-Sysmon/Operational")
            put("sysmon", "available" if ok else "degraded", "" if ok else why, service=svc)
        else:
            put("sysmon", "degraded", f"Sysmon service present but {svc}", service=svc)
        ok, why = _wevtutil_ok("Microsoft-Windows-Windows Defender/Operational")
        put("defender", "available" if ok else "unavailable", why or "observations only; Guardian never disables Defender")
        put("registry_run_keys", "available", "winreg polling")
    else:
        for n in ("event_log_system", "event_log_security", "sysmon", "defender", "registry_run_keys"):
            put(n, "unavailable", "Windows-only source (dev mode on " + platform.system() + ")")
    put("pe_parser", "available" if pe_parser else "degraded", "pefile" if pe_parser else "pefile not installed: scan limited to hashes")
    put("pe_model", "available" if model_loaded else "unavailable",
        "model loaded" if model_loaded else "No PE model installed yet (awaiting dataset). Running rules-only.")
    return {"os": platform.system(), "os_release": platform.release(), "os_build": platform.version(),
            "architecture": platform.machine(), "python": sys.version.split()[0], "admin": admin, "sources": caps}
