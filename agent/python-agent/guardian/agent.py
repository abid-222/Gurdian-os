"""Guardian agent core: collectors -> normalise -> bounded queue -> SQLite -> rules/correlation -> API subscribers."""
from __future__ import annotations
import threading, time, uuid, platform, socket, json, logging
from . import config, normalize
from .db import Database
from .queue import EventQueue
from .enrich import Enricher
from .engine import Engine, is_trusted_root
from .pe import PEModel
from . import capabilities

log = logging.getLogger("guardian")

DEFAULT_PRIVACY = {"response_actions_enabled": True, "store_command_lines": True, "redact_paths": True, "collect_network": True, "collect_registry": True,
                   "retention_days_events": config.RETENTION_DAYS["events"], "cloud_sync": False}


class Agent:
    def __init__(self, db_path=None, start_collectors=True):
        self.is_windows = config.IS_WINDOWS
        self.db = Database(db_path)
        self.queue = EventQueue()
        self.enricher = Enricher()
        self.model = PEModel()
        try:
            import pefile  # noqa
            pe_ok = True
        except ImportError:
            pe_ok = False
        self.caps = capabilities.discover(self.model.loaded, pe_ok)
        self.host_id = self.db.get_setting("host_id") or str(uuid.uuid4())
        self.db.set_setting("host_id", self.host_id)
        self.hostname = socket.gethostname()
        self.db.execute("INSERT OR REPLACE INTO hosts VALUES(?,?,?,?,?,?)",
                        (self.host_id, self.caps["os_build"], self.caps["architecture"], self.hostname,
                         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), json.dumps(self.caps["sources"])))
        self.procs: dict[str, dict] = {}
        self.pe_scores: dict[str, dict] = {}
        self.live_conns: list[dict] = []
        self.startup_items: dict[str, str] = {}
        self.resources = None
        self.paused = False
        self.started_at = time.time()
        self.subscribers: list = []
        self.engine = Engine(self)
        self.collectors = []
        self.threads: list[threading.Thread] = []
        self.stop_flag = threading.Event()
        self.privacy = {**DEFAULT_PRIVACY, **(self.db.get_setting("privacy") or {})}
        self.enricher.on_done = self._on_enriched
        from .commands import JobManager
        self.jobs = JobManager()
        try:
            from .trainer import Trainer
            self.trainer = Trainer(self)
        except ImportError:
            # trainer.py has been moved to optional/; ML training is not available in this configuration
            self.trainer = None
        self._register_model()
        self._coverage_gap_check()
        if self.db.recovery_notice:
            self.emit("guardian", "db_recovered", ts=time.time(), attributes={"note": self.db.recovery_notice})
        if start_collectors:
            self.start()

    # ---- lifecycle -------------------------------------------------------------
    def _collector_classes(self):
        from .collectors.processes import ProcessCollector
        from .collectors.network import NetworkCollector
        from .collectors.resources import ResourceCollector
        from .collectors.winevents import WinEventCollector
        from .collectors.registry import RegistryCollector
        return {"resources": ResourceCollector, "processes": ProcessCollector, "network": NetworkCollector,
                "windows_events": WinEventCollector, "registry_run_keys": RegistryCollector}

    def _collector_wanted(self, name: str) -> bool:
        if name in ("windows_events", "registry_run_keys") and not self.is_windows:
            return False
        if name == "registry_run_keys" and not self.privacy["collect_registry"]:
            return False
        if name == "network" and not self.privacy["collect_network"]:
            return False
        return True

    def _start_collector(self, name: str):
        c = self._collector_classes()[name](self)
        self.collectors.append(c)
        c.start()
        return c

    def apply_privacy(self):
        """Settings take effect immediately: start/stop optional collectors when the user toggles them (no restart needed)."""
        running = {c.name_id: c for c in self.collectors}
        for name in ("network", "registry_run_keys"):
            want = self._collector_wanted(name)
            if want and name not in running:
                self._start_collector(name)
            elif not want and name in running:
                running[name].stop()
                self.collectors.remove(running[name])
                if name == "network":
                    self.live_conns = []
                if name == "registry_run_keys":
                    self.startup_items = {}
        self.db.set_setting("privacy", self.privacy)

    def start(self):
        for name in self._collector_classes():
            if self._collector_wanted(name):
                self._start_collector(name)
        for target, name in ((self._writer, "writer"), (self._engine_loop, "engine"), (self._heartbeat, "heartbeat")):
            t = threading.Thread(target=target, name=name, daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.stop_flag.set()
        for c in self.collectors:
            c.stop()
        self.enricher.running = False

    # ---- emit ------------------------------------------------------------------------
    def emit(self, source, event_type, *, inline=False, **kw):
        if self.paused and source != "guardian":
            return None
        attrs = kw.get("attributes") or {}
        if not self.privacy["store_command_lines"]:
            attrs.pop("command_line", None)
        kw["attributes"] = attrs
        e = normalize.make_event(self.host_id, source, event_type, redact=self.privacy["redact_paths"], **kw)
        if inline:
            self.engine.on_event(e)
            e["_handled"] = True
        self.queue.put(e)
        return e

    def notify(self, kind: str, payload: dict):
        for cb in list(self.subscribers):
            try:
                cb({"type": kind, "data": payload, "ts": time.time()})
            except Exception:
                pass

    def wants_signer(self, exe: str | None) -> bool:
        return self.is_windows and bool(exe) and not is_trusted_root(exe, self.engine.policy)

    def _on_enriched(self, path: str, info: dict):
        for pi in self.procs.values():
            if pi.get("exe") == path:
                pi["sha256"] = info.get("sha256") or pi.get("sha256")
                pi["signer"] = info.get("signer", pi.get("signer"))

    def reload_model(self):
        """Load the newest model package without restarting; E1 is re-evaluated for processes seen so far."""
        from .pe import PEModel
        self.model = PEModel()
        self.pe_scores.clear()
        self.engine.evaluated = {x for x in self.engine.evaluated if x[1] != "E1"}
        self._register_model()
        self.caps["sources"]["pe_model"] = {"status": "available" if self.model.validated else "unavailable",
                                            "reason": self.model.info.get("version", "") if self.model.loaded else (self.model.warning or "no model package")}

    def score_pe(self, key: str, exe: str) -> dict | None:
        """Score one executable (read-only, never executed). Returns None for non-PE / unreadable / oversized files."""
        try:
            with open(exe, "rb") as f:
                if f.read(2) != b"MZ":
                    return None
            r = self.model.score_file(exe)
        except Exception as ex:
            log.warning("PE scoring failed for %s: %s", exe, ex)
            return None
        if r:
            self.pe_scores[key] = r
        return r

    def _register_model(self):
        if self.model.loaded:
            i = self.model.info
            self.db.execute("INSERT OR REPLACE INTO model_registry VALUES(?,?,?,?,?,?,?)",
                            (i["model_id"], i["version"], i["hash"], i["feature_schema_version"], time.time(), "active", str(config.MODEL_DIR)))

    # ---- loops -----------------------------------------------------------------------
    def _writer(self):
        while not self.stop_flag.is_set():
            batch = self.queue.drain()
            if not batch:
                continue
            try:
                self.db.insert_events(batch)
            except Exception as ex:
                log.error("batch write failed: %s", ex)
                continue
            for e in batch:
                if e.get("_handled"):
                    continue
                if e["event_type"] in ("sensor_tamper", "defender_detection", "persistence_change"):
                    try:
                        self.engine.on_event(e)
                    except Exception as ex:
                        log.error("engine.on_event: %s", ex)
            self.notify("events", {"count": len(batch), "last": batch[-1]["event_type"]})

    def _engine_loop(self):
        last_ret = 0.0
        while not self.stop_flag.is_set():
            try:
                self.engine.tick()
                if time.time() - last_ret > 3600:
                    self.db.retention(self.privacy.get("retention_days_events"))
                    last_ret = time.time()
            except Exception as ex:
                log.error("engine tick: %s", ex)
            self.stop_flag.wait(2.0)

    def _heartbeat(self):
        while not self.stop_flag.is_set():
            self.db.set_setting("heartbeat", time.time())
            self.stop_flag.wait(config.HEARTBEAT_SECONDS)

    def _coverage_gap_check(self):
        last = self.db.get_setting("heartbeat")
        if last and time.time() - last > 30:
            gap = time.time() - last
            self.emit("guardian", "coverage_gap", ts=time.time(), attributes={
                "gap_seconds": round(gap), "from": normalize.utc_iso(last),
                "note": "Agent was not running; no telemetry for this period."})

    # ---- views ---------------------------------------------------------------------
    def sources_health(self) -> dict:
        out = {k: dict(v) for k, v in self.caps["sources"].items()}
        for c in self.collectors:
            h = c.health()
            key = {"processes": "processes", "network": "network", "resources": "resources",
                   "windows_events": "event_log_system", "registry_run_keys": "registry_run_keys"}.get(c.name_id)
            if key in out and h["status"] == "stalled" and out[key]["status"] == "available":
                out[key]["status"], out[key]["reason"] = "degraded", "collector heartbeat missing"
            if key in out:
                out[key]["collector"] = h
        if self.model.warning:
            out["pe_model"]["reason"] = self.model.warning
        return out

    def thread_status(self) -> list[dict]:
        out = []
        # Collectors (producers)
        for c in self.collectors:
            h = c.health()
            alive = bool(c.is_alive())
            out.append({
                "name": c.name_id,
                "role": "producer (collector)",
                "alive": alive,
                "status": h.get("status", "ok" if alive else "stopped"),
                "interval_s": getattr(c, "interval", None),
                "last_beat_age_s": h.get("last_beat_age_s"),
                "errors": getattr(c, "errors", 0),
                "sync_primitive": f"every {c.interval}s" if getattr(c, "interval", None) else "Timer",
            })

        # Core loop threads
        role_map = {
            "writer": ("consumer (DB batch writer)", "Condition Variable (drain)"),
            "engine": ("consumer (correlation engine)", "every 2.0s"),
            "heartbeat": ("watchdog (heartbeat)", f"every {config.HEARTBEAT_SECONDS}s"),
        }
        last_hb = self.db.get_setting("heartbeat")
        hb_age = round(time.time() - last_hb, 1) if last_hb else None

        for t in self.threads:
            role, sync_prim = role_map.get(t.name, ("consumer / worker", "thread"))
            alive = bool(t.is_alive())
            out.append({
                "name": t.name,
                "role": role,
                "alive": alive,
                "status": "ok" if alive else "stopped",
                "interval_s": config.HEARTBEAT_SECONDS if t.name == "heartbeat" else 2.0 if t.name == "engine" else None,
                "last_beat_age_s": hb_age if t.name == "heartbeat" else None,
                "errors": 0,
                "sync_primitive": sync_prim,
            })

        # Enricher worker thread
        enricher_alive = bool(getattr(self.enricher, "thread", None) and self.enricher.thread.is_alive()) if hasattr(self, "enricher") else False
        q_depth = self.enricher.q.qsize() if hasattr(self, "enricher") and hasattr(self.enricher, "q") else 0
        out.append({
            "name": "enricher",
            "role": "worker (SHA-256 / Authenticode)",
            "alive": enricher_alive,
            "status": "ok" if enricher_alive else "stopped",
            "interval_s": None,
            "last_beat_age_s": None,
            "errors": 0,
            "queue_depth": q_depth,
            "sync_primitive": "queue.Queue (Condition Variable)",
        })

        return out

    def health(self) -> dict:
        q = self.queue.stats()
        src = self.sources_health()
        degraded = [k for k, v in src.items() if v["status"] in ("degraded",)]
        unavailable = [k for k, v in src.items() if v["status"] == "unavailable"]
        overall = "paused" if self.paused else "read-only" if self.db.read_only else \
            "degraded" if (q["state"] != "ok" or any(src[k]["status"] == "degraded" for k in src if k not in ("pe_parser",))) else "ok"
        return {"status": overall, "version": config.VERSION, "host_id": self.host_id, "hostname": self.hostname,
                "uptime_s": round(time.time() - self.started_at), "paused": self.paused,
                "threads": self.thread_status(),
                "db": {"path": str(self.db.path), "size_bytes": self.db.size_bytes(), "read_only": self.db.read_only, "error": self.db.error,
                       "recovery_notice": self.db.recovery_notice,
                       "audit_chain_ok": self.db.verify_audit_chain()},
                "queue": q, "sources": src, "degraded": degraded, "unavailable": unavailable,
                "model": {"loaded": self.model.loaded, "validated": self.model.validated, **self.model.info, "warning": self.model.warning},
                "policy_version": self.engine.policy["policy_version"], "admin": self.caps["admin"],
                "os": f"{self.caps['os']} {self.caps['os_release']}", "os_build": self.caps["os_build"], "architecture": self.caps["architecture"]}
