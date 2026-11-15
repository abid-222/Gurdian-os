"""CPU / memory / disk / uptime sampling with an in-memory ring buffer for the UI graphs."""
from __future__ import annotations
import time, collections
from .base import Collector

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


class ResourceCollector(Collector):
    name_id = "resources"
    interval = 2.0

    def setup(self):
        self.history = collections.deque(maxlen=300)
        psutil.cpu_percent(None)
        self.agent.resources = self

    def tick(self):
        vm = psutil.virtual_memory()
        try:
            disk = psutil.disk_usage("C:\\" if self.agent.is_windows else "/")
        except OSError:
            disk = None
        io = psutil.net_io_counters()
        batt = None
        try:
            b = psutil.sensors_battery()
            batt = {"percent": b.percent, "plugged": b.power_plugged} if b else None
        except Exception:
            pass
        s = {"ts": time.time(), "cpu": psutil.cpu_percent(None), "mem": vm.percent, "mem_used": vm.used, "mem_total": vm.total,
             "disk": disk.percent if disk else None, "disk_free": disk.free if disk else None, "disk_total": disk.total if disk else None,
             "net_sent": io.bytes_sent, "net_recv": io.bytes_recv, "uptime": time.time() - psutil.boot_time(),
             "cpu_count": psutil.cpu_count(), "battery": batt, "load_procs": len(self.agent.procs)}
        self.history.append(s)

    def latest(self):
        return self.history[-1] if self.history else None
