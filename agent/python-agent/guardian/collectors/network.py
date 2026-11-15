"""Connection metadata via the OS connection table (Sysmon Event 3 is used when available)."""
from __future__ import annotations
import time, ipaddress
from .base import Collector

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


class NetworkCollector(Collector):
    name_id = "network"
    interval = 3.0

    def setup(self):
        self.known: dict[tuple, str] = {}
        self.first = True

    def tick(self):
        a = self.agent
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError):
            return
        now = time.time()
        current = {}
        pid_to_key = {v["pid"]: k for k, v in a.procs.items()}
        for c in conns:
            if not c.raddr:
                continue
            proto = "tcp" if c.type == 1 else "udp"
            k = (c.pid, proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
            current[k] = c
            if k in self.known:
                continue
            fid = f"{a.host_id[:8]}-{abs(hash((k, int(now)))) % 10**10}"
            self.known[k] = fid
            pkey = pid_to_key.get(c.pid)
            direction = "outbound" if c.laddr.port >= 1024 or c.status == "ESTABLISHED" else "inbound"
            a.db.execute("INSERT OR IGNORE INTO network_flows VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (fid, a.host_id, now, None, proto, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port,
                          direction, c.status, pkey, c.pid))
            if pkey and pkey in a.procs and is_public(c.raddr.ip):
                pi = a.procs[pkey]
                if pi["first_outbound_ts"] is None:
                    pi["first_outbound_ts"] = now
                    pi["first_outbound"] = f"{c.raddr.ip}:{c.raddr.port}"
            if not self.first and is_public(c.raddr.ip):
                a.emit("psutil", "network_connect", pid=c.pid, process_key=pkey,
                       image_path=a.procs.get(pkey, {}).get("exe") if pkey else None,
                       attributes={"proto": proto, "remote": f"{c.raddr.ip}:{c.raddr.port}", "status": c.status})
        for k in list(self.known):
            if k not in current:
                a.db.execute("UPDATE network_flows SET end_ts=? WHERE flow_id=?", (now, self.known.pop(k)))
        self.first = False
        a.live_conns = [{"pid": k[0], "proto": k[1], "laddr": f"{k[2]}:{k[3]}", "raddr": f"{k[4]}:{k[5]}",
                         "status": c.status, "process": (a.procs.get(pid_to_key.get(k[0]), {}) or {}).get("name", "")}
                        for k, c in current.items()]
