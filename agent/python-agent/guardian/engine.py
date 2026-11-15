"""Rules + correlation policy v1 + explainable incidents (proposal section 14)."""
from __future__ import annotations
import hashlib, json, time, threading
from . import config

SEV_ORDER = ["informational", "low", "medium", "high", "critical"]
RECOMMEND = {
    "E1": "Review the PE model score, model version and threshold; confirm the file origin and hash with an offline reputation source.",
    "E2": "Inspect the parent process and the document/script that launched it; check the signer and command line (redacted).",
    "E3": "Verify where the file came from (download, email, archive). Compare its hash with a trusted source.",
    "E4": "Check the publisher/signer. If this is a known tool, add it to the allowlist with a reason.",
    "E5": "Review the startup entry and the process that created it; remove it only if you did not expect it.",
    "E6": "Check the remote address in Network Center and whether this process normally uses the network.",
}


def is_user_writable(path: str | None, policy: dict) -> bool:
    if not path:
        return False
    p = path.lower().replace("/", "\\") if "\\" in path else path.lower()
    return any(m in p for m in policy["user_writable_markers"])


def is_trusted_root(path: str | None, policy: dict) -> bool:
    if not path:
        return False
    return any(path.lower().startswith(r) for r in policy["trusted_roots"])


def severity_for(classes: set[str], policy: dict, validated_rule_hit: bool = False) -> str:
    cdef = policy["classes"]
    n = len(classes)
    strong = sum(1 for c in classes if cdef[c]["strength"] == "strong")
    medium = sum(1 for c in classes if cdef[c]["strength"] == "medium")
    non_weak = strong + medium
    if n >= 3 and (strong >= 1 or medium >= 2):
        return "critical" if validated_rule_hit else "high"
    if (n >= 2 and (non_weak >= 1 or not policy.get("medium_requires_non_weak", False))) or strong >= 1:
        return "medium"
    if medium >= 1:
        return "low"
    return "informational"


class Engine:
    def __init__(self, agent):
        self.agent = agent
        self.db = agent.db
        self.policy = config.load_policy()
        self.lock = threading.RLock()
        self.evaluated: set[tuple[str, str]] = set()
        self.known: dict[str, dict] = {}        # key -> {name,pid,sha256}: keeps incident labels after the process has exited

    # ---- allowlist ------------------------------------------------------------
    def allowlisted(self, pi: dict) -> bool:
        rows = self.db.query("SELECT kind, value FROM allowlist")
        for r in rows:
            if r["kind"] == "sha256" and pi.get("sha256") == r["value"]:
                return True
            if r["kind"] == "path" and pi.get("exe") and pi["exe"].lower().startswith(r["value"].lower()):
                return True
        return False

    # ---- rules -> detections --------------------------------------------------
    def _det(self, cls: str, rule_id: str, pi: dict, title: str, reason: str, *, score=None, threshold=None,
             refs: list | None = None, model_version=None, ts=None):
        cdef = self.policy["classes"][cls]
        did = hashlib.sha1(f"{rule_id}|{pi['key']}|{pi.get('sha256')}".encode()).hexdigest()[:20]
        ts = ts or time.time()
        cur = self.db.execute("INSERT OR IGNORE INTO detections VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                              (did, ts, self.agent.host_id, cls, rule_id, model_version, score, threshold, cdef["strength"],
                               pi["key"], pi.get("sha256"), title, reason, json.dumps(refs or [])))
        return did if cur.rowcount else None

    def evaluate_process(self, pi: dict) -> list[str]:
        """Idempotent. Called repeatedly while a process is 'recent' so late enrichment (signer/hash) is picked up."""
        if len(self.known) > 5000:
            self.known.pop(next(iter(self.known)))
        self.known[pi["key"]] = {"name": pi["name"], "pid": pi["pid"], "sha256": pi.get("sha256")}
        if pi.get("preexisting") or self.allowlisted(pi):
            return []
        pol, new = self.policy, []
        name, parent = pi["name"], (pi.get("parent_name") or "").lower()
        exe = pi.get("exe")
        trusted = is_trusted_root(exe, pol)
        writable = is_user_writable(exe, pol)
        signer = pi.get("signer", "unknown")
        unsigned = signer in ("unsigned", "invalid")
        parents = set(pol["office_parents"]) | set(pol["script_host_parents"])
        ref = [{"type": "process", "key": pi["key"]}]

        # E2 parent-child
        if parent in parents and (name in pol["shell_children"] or (unsigned and not trusted)):
            d = self._det("E2", "R-PARENT-CHILD", pi, f"{parent} launched {name}",
                          f"Office or script host '{parent}' started '{name}' (signer: {signer}).", refs=ref + [{"type": "parent", "name": parent}])
            d and new.append(d)
        # E3 drop-and-execute
        created = pi.get("exe_created_ts")
        if created and writable and not trusted and -2.0 <= pi["start_ts"] - created <= pol["drop_and_execute_seconds"]:
            d = self._det("E3", "R-DROP-EXEC", pi, f"{name} executed {int(pi['start_ts'] - created)} s after it was created",
                          f"Executable in a user-writable path was created and run within {pol['drop_and_execute_seconds']} s.",
                          refs=ref + [{"type": "file", "path": exe}])
            d and new.append(d)
        # E4 signer/path context
        if unsigned and writable and not trusted:
            d = self._det("E4", "R-UNSIGNED-WRITABLE", pi, f"Unsigned binary in user-writable path: {name}",
                          f"Signature status '{signer}' and the image sits in a user-writable location.", refs=ref)
            d and new.append(d)
        # E6 outbound within window (only for non-OS binaries, to keep volume sane)
        fo = pi.get("first_outbound_ts")
        if fo and not trusted and 0 <= fo - pi["start_ts"] <= pol["outbound_after_start_seconds"]:
            d = self._det("E6", "R-EARLY-OUTBOUND", pi, f"{name} opened an outbound connection {int(fo - pi['start_ts'])} s after start",
                          f"New outbound connection to {pi.get('first_outbound', 'a public address')} shortly after process start.", refs=ref)
            d and new.append(d)
        # E1 PE model: only a VALIDATED model (threshold + calibration chosen on validation data, spec 11.3/14.3) counts as evidence.
        m = self.agent.model
        if m.validated and exe and not trusted and pi.get("sha256") and (pi["key"], "E1") not in self.evaluated:
            self.evaluated.add((pi["key"], "E1"))
            r = self.agent.score_pe(pi["key"], exe)
            if r and r["score"] >= r["threshold"]:
                d = self._det("E1", "M-PE-LGBM", pi, f"PE model score {r['score']:.2f} for {name}",
                              f"Calibrated PE score {r['score']:.2f} is above the validation-chosen threshold ({r['threshold']}); model {r['model_version']}.",
                              score=r["score"], threshold=r["threshold"], model_version=r["model_version"], refs=ref)
                d and new.append(d)
        return new

    # ---- event-driven observations ------------------------------------------------
    def on_event(self, e: dict):
        et, a = e["event_type"], e.get("attributes") or {}
        if et == "sensor_tamper":
            kind = a.get("kind")
            obs = self.policy["observations"].get(kind)
            if obs:
                self._observation(kind, obs, e)
        elif et == "defender_detection":
            self._observation("defender_detection", self.policy["observations"]["defender_detection"], e)
        elif et == "persistence_change" and a.get("run_key"):
            pkey = (e.get("process") or {}).get("process_guid")
            pi = self.agent.procs.get(pkey) if pkey else None
            if pi and not self.allowlisted(pi) and not pi.get("preexisting"):
                self._det("E5", "R-PERSIST-RUNKEY", pi, f"{pi['name']} changed a startup (Run) key",
                          f"Sysmon registry event changed {a.get('target', 'a Run key')}.", refs=[{"type": "event", "id": e["event_id"]}])
            # unattributed startup changes stay quiet timeline entries (informational, spec 11.3)

    def _observation(self, kind: str, obs: dict, e: dict):
        iid = hashlib.sha1(f"obs|{kind}|{e['event_id']}".encode()).hexdigest()[:20]
        now = e["ts"]
        sev = obs["severity"]
        if sev == "informational":     # quiet timeline entry only (spec 11.3)
            return
        self.db.execute("INSERT OR IGNORE INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (iid, "open", sev, SEV_ORDER.index(sev) * 20 + 10, obs["title"],
                         f"Observation from {e['source']}: {json.dumps(e.get('attributes') or {})[:300]}", None, "(system)", None, None,
                         now, now, None, json.dumps([]), json.dumps([]),
                         "Observation, not proof of compromise. Sensor-tamper conditions are detected and reported, never prevented (A2 out of scope).",
                         self.policy["policy_version"], 1 if e["source"] == "simulation" else 0, None, None,
                         json.dumps(["Check who changed the sensor and whether it was expected.", "Review the timeline around this time."])))
        self.agent.notify("incident", {"id": iid, "severity": sev, "title": obs["title"]})

    # ---- correlation -----------------------------------------------------------------
    def correlate(self):
        """Group detections by process key, merge child->parent chains and same-hash within the merge window."""
        with self.lock:
            dets = self.db.query("SELECT * FROM detections WHERE process_key IS NOT NULL ORDER BY ts")
            if not dets:
                return
            by_proc: dict[str, list] = {}
            for d in dets:
                by_proc.setdefault(d["process_key"], []).append(d)
            # union-find over process keys
            parent = {k: k for k in by_proc}

            def find(x):
                while parent[x] != x:
                    parent[x] = parent[parent[x]]
                    x = parent[x]
                return x

            procs = self.agent.procs
            merge = self.policy["incident_merge_window_seconds"]
            keys = list(by_proc)
            for k in keys:
                pi = procs.get(k)
                pk = pi.get("parent_key") if pi else None
                if pk in by_proc and abs(by_proc[k][0]["ts"] - by_proc[pk][0]["ts"]) <= merge:
                    parent[find(k)] = find(pk)
            by_hash: dict[str, str] = {}
            for k in keys:
                h = by_proc[k][0].get("sha256")
                if h:
                    if h in by_hash and abs(by_proc[k][0]["ts"] - by_proc[by_hash[h]][0]["ts"]) <= merge:
                        parent[find(k)] = find(by_hash[h])
                    else:
                        by_hash[h] = k
            groups: dict[str, list] = {}
            for k in keys:
                groups.setdefault(find(k), []).extend(by_proc[k])
            for root, ds in groups.items():
                self._upsert_incident(root, ds)

    def _upsert_incident(self, root: str, ds: list[dict]):
        classes = {d["evidence_class"] for d in ds}
        validated = any(d["rule_id"] in self.policy["validated_high_precision_rules"] for d in ds)
        sev = severity_for(classes, self.policy, validated)
        if sev == "informational":
            return                                   # quiet: stays a timeline entry
        iid = "INC-" + hashlib.sha1(root.encode()).hexdigest()[:10]
        import collections
        lead = collections.Counter(d["process_key"] for d in ds).most_common(1)[0][0]
        pi = self.agent.procs.get(lead) or self.known.get(lead) or {}
        if not pi.get("name"):                           # e.g. after a restart: fall back to what the incident already stored
            old = self.db.one("SELECT process_name, pid, sha256 FROM incidents WHERE incident_id=?", (iid,)) or {}
            pi = {"name": old.get("process_name"), "pid": old.get("pid"), "sha256": old.get("sha256")}
        first = min(d["ts"] for d in ds)
        cdef = self.policy["classes"]
        risk = min(100, sum(cdef[c]["weight"] for c in classes) * 12 + (10 if sev in ("high", "critical") else 0))
        names = ", ".join(sorted({d["title"] for d in ds}))[:240]
        title = f"{sev.capitalize()} incident: {pi.get('name') or ds[0]['title']}"
        summary = " → ".join(d["title"] for d in sorted(ds, key=lambda x: x["ts"]))
        caveats = []
        src = self.agent.caps["sources"]
        if src.get("sysmon", {}).get("status") != "available":
            caveats.append("Sysmon unavailable/degraded: persistence and file-create evidence limited, confidence lowered.")
        if not self.agent.model.validated:
            caveats.append("No validated PE model installed: E1 evidence unavailable, rules-only. Scores are not probabilities.")
        caveats.append("Unknown is not malicious. This is a reason to investigate, not proof of an attack.")
        steps = sorted({RECOMMEND[c] for c in classes})
        sim = 1 if any("sim:" in (d["process_key"] or "") for d in ds) else 0
        ex = self.db.one("SELECT status, decision FROM incidents WHERE incident_id=?", (iid,))
        status = ex["status"] if ex else "open"
        # groups can merge later (parent/child, same hash): absorb superseded partial incidents, keep any user decision
        keys = sorted({d["process_key"] for d in ds})
        ph = ",".join("?" * len(keys))
        for old in self.db.query(f"SELECT incident_id, status FROM incidents WHERE process_key IN ({ph}) AND incident_id != ?", keys + [iid]):
            if old["status"] != "open" and status == "open":
                status = old["status"]
            self.db.execute("DELETE FROM incidents WHERE incident_id=?", (old["incident_id"],))
        self.db.execute("INSERT INTO incidents VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                        "ON CONFLICT(incident_id) DO UPDATE SET severity=excluded.severity, risk=excluded.risk, title=excluded.title, "
                        "summary=excluded.summary, process_key=excluded.process_key, process_name=excluded.process_name, pid=excluded.pid, sha256=excluded.sha256, updated_at=excluded.updated_at, classes=excluded.classes, detection_ids=excluded.detection_ids, "
                        "caveat=excluded.caveat, steps=excluded.steps",
                        (iid, status, sev, risk, title, summary, lead, pi.get("name"), pi.get("pid"), pi.get("sha256") or ds[0].get("sha256"),
                         first, time.time(), None, json.dumps(sorted(classes)), json.dumps([d["detection_id"] for d in ds]),
                         " ".join(caveats), self.policy["policy_version"], sim, None, None, json.dumps(steps)))
        if not ex:
            self.agent.notify("incident", {"id": iid, "severity": sev, "title": title})

    def tick(self):
        now = time.time()
        for pi in list(self.agent.procs.values()):
            if pi.get("preexisting"):
                continue
            if now - pi["start_ts"] < 900 or pi.get("simulated"):
                self.evaluate_process(pi)
        self.correlate()
