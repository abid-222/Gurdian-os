"""SQLite (WAL) storage with forward-only migrations, retention and a hash-chained audit log."""
from __future__ import annotations
import sqlite3, json, time, shutil, hashlib, threading, pathlib
from . import config


class Database:
    def __init__(self, path: pathlib.Path | str | None = None):
        self.path = pathlib.Path(path) if path else config.data_dir() / "guardian.db"
        self.lock = threading.RLock()
        self.read_only = False
        self.error: str | None = None
        self.recovery_notice: str | None = None
        try:
            self._open()
            healthy = self._healthy()
        except sqlite3.DatabaseError:             # e.g. "file is not a database"
            healthy = False
        if not healthy:
            self._recover()           # spec 18.4: copy the damaged file aside, start a fresh database, tell the user
        self.migrate()

    def _open(self):
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA wal_autocheckpoint=1000")

    def _healthy(self) -> bool:
        try:
            r = self.conn.execute("PRAGMA quick_check").fetchone()
            return bool(r) and r[0] == "ok"
        except sqlite3.DatabaseError:
            return False

    def _recover(self):
        try:
            self.conn.close()
        except Exception:
            pass
        aside = self.path.with_name(f"{self.path.stem}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}{self.path.suffix}")
        try:
            shutil.move(str(self.path), str(aside))
            for ext in ("-wal", "-shm"):
                side = pathlib.Path(str(self.path) + ext)
                if side.exists():
                    side.unlink()
            self._open()
            self.recovery_notice = f"Database failed its integrity check. The damaged file was kept as {aside.name}; a fresh database was created."
        except Exception as e:                      # could not even move it: fall back to read-only mode
            self.read_only, self.error = True, f"database unusable and recovery failed: {e}"
            self._open()

    # ---- health / migration -------------------------------------------------
    def migrate(self):
        self.conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL)")
        done = {r[0] for r in self.conn.execute("SELECT version FROM schema_migrations")}
        files = sorted(config.MIGRATIONS_DIR.glob("*.sql"))
        for f in files:
            ver = int(f.name.split("_")[0])
            if ver in done:
                continue
            backup = self.path.with_suffix(f".bak{ver}")
            try:
                self.conn.execute("PRAGMA wal_checkpoint(FULL)")
                shutil.copy2(self.path, backup)
                self.conn.executescript(f.read_text(encoding="utf-8"))
                self.conn.execute("INSERT INTO schema_migrations VALUES(?,?)", (ver, time.time()))
            except Exception as e:  # restore the copy and go read-only (spec 10.4)
                self.conn.close()
                shutil.copy2(backup, self.path)
                self.conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
                self.conn.row_factory = sqlite3.Row
                self.read_only, self.error = True, f"migration {ver} failed: {e}"
                return

    # ---- helpers -------------------------------------------------------------
    def execute(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params)

    def query(self, sql, params=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def insert_events(self, events: list[dict]):
        if self.read_only or not events:
            return
        rows = []
        for e in events:
            p = e.get("process") or {}
            rows.append((e["event_id"], e["schema_version"], e["host_id"], e["ts"], e["timestamp_utc"], e["source"],
                         e["event_type"], p.get("process_guid"), p.get("pid"), p.get("parent_pid"), p.get("image_path"),
                         p.get("sha256"), json.dumps(e.get("attributes") or {}), json.dumps(e.get("privacy_flags") or []),
                         e.get("severity")))
        with self.lock:
            self.conn.execute("BEGIN")
            try:
                self.conn.executemany("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                self.conn.execute("COMMIT")           # one transaction per batch
            except Exception:
                self.conn.execute("ROLLBACK")
                raise

    # ---- settings ------------------------------------------------------------
    def get_setting(self, key, default=None):
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r["value"]) if r else default

    def set_setting(self, key, value):
        self.execute("INSERT INTO settings VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                     (key, json.dumps(value), time.time()))

    # ---- audit (append-only, hash chain) ---------------------------------------
    def audit(self, actor: str, action: str, target: str = "", result: str = "ok", detail: str = ""):
        with self.lock:
            last = self.one("SELECT hash FROM actions_audit ORDER BY action_id DESC LIMIT 1")
            prev = last["hash"] if last else "GENESIS"
            ts = time.time()
            h = hashlib.sha256(f"{prev}|{ts}|{actor}|{action}|{target}|{result}|{detail}".encode()).hexdigest()
            self.execute("INSERT INTO actions_audit(ts,actor,action,target,result,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?)",
                         (ts, actor, action, target, result, detail, prev, h))

    def verify_audit_chain(self) -> bool:
        prev = "GENESIS"
        for r in self.query("SELECT * FROM actions_audit ORDER BY action_id"):
            h = hashlib.sha256(f"{prev}|{r['ts']}|{r['actor']}|{r['action']}|{r['target']}|{r['result']}|{r['detail']}".encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != h:
                return False
            prev = h
        return True

    # ---- retention -------------------------------------------------------------
    def retention(self, events_days: int | None = None):
        """Age out data. `events_days` is the user's privacy setting; it overrides the 14-day default for raw events and flows."""
        if self.read_only:
            return {}
        now, out = time.time(), {}
        day = 86400
        r = dict(config.RETENTION_DAYS)
        if events_days:
            r["events"] = int(events_days)
        cur = self.execute("DELETE FROM events WHERE ts < ?", (now - r["events"] * day,)); out["events"] = cur.rowcount
        cur = self.execute("DELETE FROM process_snapshots WHERE ts < ?", (now - r["process_snapshots"] * day,)); out["snapshots"] = cur.rowcount
        cur = self.execute("DELETE FROM network_flows WHERE start_ts < ?", (now - r["events"] * day,)); out["flows"] = cur.rowcount
        self.execute("DELETE FROM detections WHERE ts < ?", (now - r["detections"] * day,))
        self.execute("DELETE FROM incidents WHERE opened_at < ?", (now - r["incidents"] * day,))
        # size cap: remove oldest raw events first
        try:
            while self.path.stat().st_size > config.DB_SIZE_CAP:
                self.execute("DELETE FROM events WHERE event_id IN (SELECT event_id FROM events ORDER BY ts LIMIT 5000)")
                self.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                if not self.one("SELECT 1 FROM events LIMIT 1"):
                    break
        except OSError:
            pass
        return out

    def size_bytes(self) -> int:
        try:
            return self.path.stat().st_size
        except OSError:
            return 0

    def wipe_telemetry(self):
        for t in ("events", "process_snapshots", "network_flows", "detections", "incidents", "incident_notes"):
            self.execute(f"DELETE FROM {t}")
        self.execute("VACUUM")
