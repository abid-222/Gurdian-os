"""Startup (Run key) change watcher. Attribution to a process needs Sysmon 12-14; here we record the change only."""
from __future__ import annotations
from .base import Collector
from .. import config

KEYS = []
if config.IS_WINDOWS:
    import winreg
    KEYS = [(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)")]


def read_run_keys() -> dict[str, str]:
    out = {}
    if not config.IS_WINDOWS:
        return out
    import winreg
    for hive, path, label in KEYS:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                        out[f"{label}\\{name}"] = str(val)
                        i += 1
                    except OSError:
                        break
        except OSError:
            continue
    return out


class RegistryCollector(Collector):
    name_id = "registry_run_keys"
    interval = 10.0

    def setup(self):
        self.base = read_run_keys()
        self.agent.startup_items = self.base

    def tick(self):
        cur = read_run_keys()
        for k, v in cur.items():
            if k not in self.base or self.base[k] != v:
                self.agent.emit("registry", "persistence_change", attributes={"target": k, "value": v[:300], "run_key": True,
                                                                                "attributed": False})
        self.base = cur
        self.agent.startup_items = cur
