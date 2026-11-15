"""Process inventory + start/end events by diffing the live process table (psutil)."""
from __future__ import annotations
import os, time
from .base import Collector
from .. import config

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def process_key(pid: int, create_time: float) -> str:
    """PIDs get reused, so identity = pid + start time (spec 9.1)."""
    return f"{pid}:{int(create_time * 1000)}"


def file_created_ts(path: str | None) -> float | None:
    try:
        st = os.stat(path)
        return getattr(st, "st_birthtime", st.st_ctime)
    except (OSError, TypeError):
        return None


class ProcessCollector(Collector):
    """Fast new-process detection without admin rights or ETW.

    Every 0.5 s only the cheap PID list is diffed (psutil.pids()); full attributes are read just for PIDs that are new. Every
    4th tick (2 s) the whole table is refreshed for CPU/RSS, exits and PID-reuse checks. This catches processes that live
    for well under a second, which a plain 2 s full scan misses. (Sysmon/ETW remain the exact source; see docs.)"""
    name_id = "processes"
    interval = 0.5
    ATTRS = ["pid", "ppid", "name", "exe", "create_time", "memory_info", "cpu_percent", "username", "status"]

    def setup(self):
        self.first = True
        self.last_snapshot = 0.0
        self.tick_no = 0
        self.pid_key: dict[int, str] = {}

    # -- helpers ---------------------------------------------------------------------
    def _read(self, pid: int):
        try:
            p = psutil.Process(pid)
            info = p.as_dict(attrs=self.ATTRS, ad_value=None)
            if info.get("create_time") is None:
                return None
            if time.time() - info["create_time"] < 0.3:      # image may not be resolved yet (fork->exec window): look again
                time.sleep(0.06)
                info = p.as_dict(attrs=self.ATTRS, ad_value=None)
            return info if info.get("create_time") is not None else None
        except (psutil.Error, OSError):
            return None

    def _register(self, i: dict, seen_lookup=None):
        a = self.agent
        table = a.procs
        key = process_key(i["pid"], i["create_time"])
        if key in table:
            return key
        exe = i.get("exe")
        ppid = i.get("ppid") or 0
        parent_key = self.pid_key.get(ppid)
        parent = table.get(parent_key) if parent_key else None
        if parent is None and seen_lookup and ppid in seen_lookup:
            parent = {"name": (seen_lookup[ppid].get("name") or "").lower(), "key": None}
        enr = a.enricher.get(exe)
        mi = i.get("memory_info")
        pi = {"key": key, "pid": i["pid"], "ppid": ppid, "parent_key": parent_key,
              "parent_name": (parent or {}).get("name", "") if parent else "",
              "name": (i.get("name") or "").lower(), "exe": exe, "start_ts": i["create_time"],
              "exe_created_ts": file_created_ts(exe), "preexisting": self.first,
              "sha256": enr.get("sha256"), "signer": enr.get("signer", "unknown"),
              "cpu": i.get("cpu_percent") or 0.0, "rss": mi.rss if mi else 0, "cmdline": None,
              "simulated": False, "first_outbound_ts": None}
        if not self.first:
            try:
                pi["cmdline"] = " ".join(psutil.Process(i["pid"]).cmdline())
            except (psutil.Error, OSError):
                pass
        table[key] = pi
        self.pid_key[i["pid"]] = key
        if exe:
            a.enricher.request(exe, want_signer=a.wants_signer(exe))
        if not self.first:
            a.emit("psutil", "process_start", pid=pi["pid"], parent_pid=ppid, process_key=key, image_path=exe,
                   sha256=pi["sha256"], ts=pi["start_ts"],
                   attributes={"name": pi["name"], "parent_name": pi["parent_name"], "command_line": pi["cmdline"],
                               "exe_created_ts": pi["exe_created_ts"]})
        return key

    def _end(self, key: str, now: float):
        a = self.agent
        pi = a.procs.pop(key, None)
        if not pi:
            return
        if self.pid_key.get(pi["pid"]) == key:
            self.pid_key.pop(pi["pid"], None)
        a.emit("psutil", "process_end", pid=pi["pid"], process_key=key, image_path=pi.get("exe"),
               sha256=pi.get("sha256"), attributes={"name": pi["name"]}, ts=now)

    # -- main loop -------------------------------------------------------------------
    def tick(self):
        a = self.agent
        now = time.time()
        self.tick_no += 1
        table = a.procs
        if self.first or self.tick_no % 4 == 0:
            # full refresh: attributes for everything, exits, PID reuse, CPU/RSS
            seen = {}
            for p in psutil.process_iter(self.ATTRS, ad_value=None):
                i = p.info
                if i.get("pid") is None or i.get("create_time") is None:
                    continue
                seen[process_key(i["pid"], i["create_time"])] = i
            by_pid = {i["pid"]: i for i in seen.values()}
            for key in list(table.keys()):
                if key not in seen and not table[key].get("simulated"):
                    self._end(key, now)
            for key, i in seen.items():
                if key in table:
                    pi = table[key]
                    pi["cpu"] = i.get("cpu_percent") or 0.0
                    mi = i.get("memory_info")
                    pi["rss"] = mi.rss if mi else 0
                    self.pid_key[i["pid"]] = key
                    nm, ex = (i.get("name") or "").lower(), i.get("exe")
                    if not pi.get("simulated") and ((ex and ex != pi.get("exe")) or (nm and nm != pi["name"])):
                        # identity resolved late (image path was unavailable or the process re-exec'd): update and re-evaluate
                        pi.update({"name": nm, "exe": ex, "exe_created_ts": file_created_ts(ex)})
                        enr = a.enricher.get(ex)
                        pi["sha256"], pi["signer"] = enr.get("sha256"), enr.get("signer", "unknown")
                        if ex:
                            a.enricher.request(ex, want_signer=a.wants_signer(ex))
                else:
                    self._register(i, by_pid)
            self.first = False
        else:
            # cheap path: diff the PID list, read attributes only for new PIDs
            pids = set(psutil.pids())
            known = {pi["pid"]: k for k, pi in table.items() if not pi.get("simulated")}
            for pid, key in list(known.items()):
                if pid not in pids:
                    self._end(key, now)
            for pid in pids - set(known):
                info = self._read(pid)
                if info:
                    self._register(info)
        # periodic top-N snapshots for trend (spec: process_snapshots, 7 d retention)
        if now - self.last_snapshot > 60:
            self.last_snapshot = now
            top = sorted(table.values(), key=lambda v: v.get("rss", 0), reverse=True)[:30]
            rows = [(a.host_id, now, v["pid"], v["key"], v["name"], v.get("exe"), v.get("sha256"), v.get("signer"),
                     v.get("cpu"), v.get("rss")) for v in top]
            try:
                with a.db.lock:
                    a.db.conn.executemany(
                        "INSERT INTO process_snapshots(host_id,ts,pid,process_key,name,image,sha256,signer,cpu,rss) VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
            except Exception:
                pass
