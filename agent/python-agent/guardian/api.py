"""Local FastAPI: loopback only, per-session token, Host/Origin checks, schema-validated input, rate-limited (spec 17.2)."""
from __future__ import annotations
import asyncio, hmac, json, time, collections, secrets
from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from . import config, commands, pe, simulate

SEVERITIES = ["informational", "low", "medium", "high", "critical"]


class PrivacyUpdate(BaseModel):
    response_actions_enabled: bool | None = None
    store_command_lines: bool | None = None
    redact_paths: bool | None = None
    collect_network: bool | None = None
    collect_registry: bool | None = None
    retention_days_events: int | None = Field(None, ge=1, le=90)


class ScanReq(BaseModel):
    path: str = Field(..., max_length=1024)


class TermReq(BaseModel):
    line: str = Field(..., max_length=512)


class DismissReq(BaseModel):
    reason: str = Field(..., min_length=3, max_length=300)


class AllowReq(BaseModel):
    kind: str = Field(..., pattern="^(sha256|path)$")
    value: str = Field(..., min_length=3, max_length=1024)
    reason: str = Field("", max_length=300)


class ExecReq(BaseModel):
    action: str = Field(..., pattern="^(terminate|suspend|resume|quarantine)$")
    target: str = Field(..., max_length=300)
    confirm_name: str = Field(..., max_length=200)


class PreviewReq(BaseModel):
    action: str = Field(..., pattern="^(terminate|suspend|resume|quarantine|block)$")
    target: str = Field(..., max_length=300)


class NoteReq(BaseModel):
    body: str = Field(..., min_length=1, max_length=2000)


class TrainReq(BaseModel):
    source: str = Field("auto", pattern="^(auto|ember|folders|csv)$")
    max_rows: int = Field(150000, ge=1000, le=2000000)


class PauseReq(BaseModel):
    paused: bool


class WipeReq(BaseModel):
    confirm: str


def create_app(agent, token: str, port: int | None = None, token_issued: float | None = None) -> FastAPI:
    app = FastAPI(title="Smart OS Guardian local API", version=config.VERSION, docs_url=None, redoc_url=None, openapi_url=None)
    issued = token_issued or time.time()
    app.state.allowed_hosts = None
    hits: dict[str, collections.deque] = collections.defaultdict(collections.deque)
    auth_failures: list[dict] = []

    def host_ok(host: str | None) -> bool:
        if not host:
            return False
        h = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        return h in ("127.0.0.1", "localhost", "[::1]")

    def origin_ok(origin: str | None) -> bool:
        if not origin:
            return True                      # same-origin GETs and non-browser clients send no Origin
        o = origin.split("://", 1)[-1]
        return host_ok(o)                    # loopback names only; no wildcard CORS

    def token_ok(t: str | None) -> bool:
        return bool(t) and hmac.compare_digest(t.encode(), token.encode()) and (time.time() - issued) < config.TOKEN_TTL_SECONDS

    @app.middleware("http")
    async def guard(request: Request, call_next):
        if not host_ok(request.headers.get("host")) or not origin_ok(request.headers.get("origin")):
            return JSONResponse({"detail": "forbidden host/origin"}, status_code=403)
        if request.url.path.startswith("/api/"):
            if request.url.path == P + "/auth/session":
                return JSONResponse({"token": token, "authenticated": True})
            if not token_ok(request.headers.get("x-guardian-token")):
                auth_failures.append({"ts": time.time(), "path": request.url.path})
                del auth_failures[:-200]
                agent.db.audit("api", "auth_failure", request.url.path, "denied")
                return JSONResponse({"detail": "invalid or expired token"}, status_code=401)
            dq = hits[token]
            now = time.time()
            while dq and dq[0] < now - 1:
                dq.popleft()
            if len(dq) >= 200:
                return JSONResponse({"detail": "rate limit"}, status_code=429)
            dq.append(now)
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self' ws://127.0.0.1:* ws://localhost:*"
        return resp

    P = "/api/v1"

    # ---- health / system ------------------------------------------------------------------
    @app.get(P + "/health")
    def health():
        return agent.health()

    @app.get(P + "/capabilities")
    def caps():
        return agent.caps

    @app.get(P + "/system/summary")
    def summary():
        s = agent.resources.latest() if agent.resources else None
        return {"latest": s, "process_count": len(agent.procs), "connection_count": len(agent.live_conns),
                "incidents_open": agent.db.one("SELECT COUNT(*) c FROM incidents WHERE status='open'")["c"]}

    @app.get(P + "/system/history")
    def history():
        return {"samples": list(agent.resources.history) if agent.resources else []}

    @app.get(P + "/system/startup")
    def startup():
        return {"items": [{"location": k, "command": v} for k, v in agent.startup_items.items()],
                "available": agent.is_windows}

    @app.get(P + "/system/services")
    def services():
        out = []
        if agent.is_windows:
            import psutil
            for s in psutil.win_service_iter():
                try:
                    d = s.as_dict()
                    out.append({"name": d["name"], "display": d["display_name"], "status": d["status"], "start": d["start_type"]})
                except Exception:
                    continue
        return {"items": out[:400], "available": agent.is_windows}

    @app.get(P + "/system/threads")
    def threads():
        return {"threads": agent.thread_status()}

    @app.post(P + "/collection")
    def collection(req: PauseReq):
        agent.paused = req.paused
        agent.db.audit("user", "pause_collection" if req.paused else "resume_collection")
        agent.notify("health", {"paused": agent.paused})
        return {"paused": agent.paused}

    # ---- processes / network ----------------------------------------------------------------
    @app.get(P + "/processes")
    def processes(limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0), sort: str = "rss", q: str = "", order: str = "desc"):
        rows = list(agent.procs.values())
        if q:
            ql = q.lower()
            rows = [r for r in rows if ql in r["name"] or ql in str(r["pid"]) or ql in (r.get("exe") or "").lower()]
        if sort not in ("rss", "cpu", "pid", "name", "start_ts"):
            raise HTTPException(400, "bad sort")
        rows.sort(key=lambda r: r.get(sort) or 0 if sort != "name" else r["name"], reverse=(order == "desc"))
        inc = {r["process_key"]: r["severity"] for r in agent.db.query("SELECT process_key, severity FROM incidents WHERE process_key IS NOT NULL AND status='open'")}
        slim = [{k: r.get(k) for k in ("key", "pid", "ppid", "parent_key", "name", "exe", "start_ts", "cpu", "rss", "signer", "sha256",
                                       "parent_name", "simulated", "preexisting")} | {"incident": inc.get(r["key"])} for r in rows[offset:offset + limit]]
        return {"total": len(rows), "items": slim}

    @app.get(P + "/processes/{key:path}")
    def process_detail(key: str):
        pi = agent.procs.get(key)
        if not pi:
            raise HTTPException(404, "process not found (it may have exited)")
        children = [{"pid": c["pid"], "name": c["name"], "key": c["key"]} for c in agent.procs.values() if c.get("parent_key") == key]
        dets = agent.db.query("SELECT * FROM detections WHERE process_key=? ORDER BY ts", (key,))
        ev = agent.db.query("SELECT ts, source, event_type, attributes FROM events WHERE process_key=? ORDER BY ts DESC LIMIT 50", (key,))
        from .normalize import redact_cmdline, redact_path
        safe = dict(pi)
        safe["cmdline"] = redact_cmdline(pi.get("cmdline"))[0]
        safe["exe"] = redact_path(pi.get("exe"), agent.privacy["redact_paths"])[0]
        return {"process": safe, "children": children, "detections": dets, "events": ev, "pe": agent.pe_scores.get(key)}

    @app.get(P + "/network/connections")
    def connections(q: str = ""):
        rows = agent.live_conns
        if q:
            rows = [r for r in rows if q.lower() in json.dumps(r).lower()]
        return {"items": rows[:1000], "total": len(rows)}

    @app.get(P + "/network/flows")
    def flows(limit: int = Query(200, ge=1, le=1000)):
        return {"items": agent.db.query("SELECT * FROM network_flows ORDER BY start_ts DESC LIMIT ?", (limit,))}

    # ---- events / alerts ------------------------------------------------------------------
    @app.get(P + "/events")
    def events(since: float | None = None, until: float | None = None, type: str | None = None, source: str | None = None,
               pid: int | None = None, process_key: str | None = None, sha256: str | None = None, q: str | None = None,
               limit: int = Query(200, ge=1, le=1000), before: float | None = None):
        where, par = [], []
        for clause, val in (("ts>=?", since), ("ts<=?", until), ("event_type=?", type), ("source=?", source), ("pid=?", pid),
                            ("process_key=?", process_key), ("sha256=?", sha256), ("ts<?", before)):
            if val is not None:
                where.append(clause); par.append(val)
        if q:
            if len(q) in (16, 32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in q):   # looks like a hash: match the hash column too
                where.append("(sha256 LIKE ? OR attributes LIKE ? OR image_path LIKE ?)"); par += [f"{q.lower()}%", f"%{q}%", f"%{q}%"]
            else:
                where.append("(attributes LIKE ? OR image_path LIKE ?)"); par += [f"%{q}%", f"%{q}%"]
        sql = "SELECT * FROM events" + (" WHERE " + " AND ".join(where) if where else "") + " ORDER BY ts DESC LIMIT ?"
        rows = agent.db.query(sql, par + [limit])
        for r in rows:
            r["attributes"] = json.loads(r["attributes"] or "{}")
            r["privacy_flags"] = json.loads(r["privacy_flags"] or "[]")
        return {"items": rows}

    @app.get(P + "/events/stats")
    def event_stats():
        rows = agent.db.query("SELECT event_type, COUNT(*) c FROM events WHERE ts>? GROUP BY event_type", (time.time() - 3600,))
        return {"last_hour": {r["event_type"]: r["c"] for r in rows}, "queue": agent.queue.stats()}

    def _inc_row(r):
        for k in ("classes", "detection_ids", "steps"):
            r[k] = json.loads(r[k] or "[]")
        return r

    @app.get(P + "/alerts")
    def alerts(status: str | None = None, limit: int = Query(100, ge=1, le=500)):
        sql = "SELECT * FROM incidents" + (" WHERE status=?" if status else "") + " ORDER BY opened_at DESC LIMIT ?"
        rows = agent.db.query(sql, ([status] if status else []) + [limit])
        return {"items": [_inc_row(r) for r in rows]}

    @app.get(P + "/alerts/{iid}")
    def alert_detail(iid: str):
        r = agent.db.one("SELECT * FROM incidents WHERE incident_id=?", (iid,))
        if not r:
            raise HTTPException(404, "incident not found")
        r = _inc_row(r)
        dets = [d for d in agent.db.query("SELECT * FROM detections ORDER BY ts") if d["detection_id"] in r["detection_ids"]]
        for d in dets:
            d["evidence_refs"] = json.loads(d["evidence_refs"] or "[]")
        cdef = agent.engine.policy["classes"]
        for d in dets:
            d["class_name"] = cdef[d["evidence_class"]]["name"]
        audit = agent.db.query("SELECT ts, actor, action, result, detail FROM actions_audit WHERE target=? ORDER BY ts", (iid,))
        return {"incident": r, "detections": dets, "audit": audit, "policy": {"version": agent.engine.policy["policy_version"],
                "join_window_s": agent.engine.policy["join_window_seconds"], "merge_window_s": agent.engine.policy["incident_merge_window_seconds"]},
                "model": {"loaded": agent.model.loaded, "info": agent.model.info}}

    @app.get(P + "/alerts/{iid}/notes")
    def notes(iid: str):
        return {"items": agent.db.query("SELECT note_id, ts, author, body FROM incident_notes WHERE incident_id=? ORDER BY ts", (iid,))}

    @app.post(P + "/alerts/{iid}/notes")
    def add_note(iid: str, req: NoteReq):
        if not agent.db.one("SELECT 1 FROM incidents WHERE incident_id=?", (iid,)):
            raise HTTPException(404, "incident not found")
        agent.db.execute("INSERT INTO incident_notes(incident_id, ts, author, body) VALUES(?,?,?,?)", (iid, time.time(), "user", req.body.strip()))
        agent.db.audit("user", "note_add", iid, "ok", req.body.strip()[:120])
        return {"ok": True}

    @app.get(P + "/alerts/{iid}/export")
    def export_incident(iid: str):
        r = agent.db.one("SELECT * FROM incidents WHERE incident_id=?", (iid,))
        if not r:
            raise HTTPException(404, "incident not found")
        r = _inc_row(r)
        dets = [d for d in agent.db.query("SELECT * FROM detections ORDER BY ts") if d["detection_id"] in r["detection_ids"]]
        keys = sorted({d["process_key"] for d in dets if d["process_key"]})
        ev = []
        if keys:
            ev = agent.db.query(f"SELECT ts, source, event_type, pid, image_path, sha256, attributes FROM events WHERE process_key IN ({','.join('?' * len(keys))}) ORDER BY ts", keys)
        data = {"exported_at": time.time(), "host": agent.hostname, "policy_version": agent.engine.policy["policy_version"], "incident": r,
                "detections": dets, "events": ev,
                "notes": agent.db.query("SELECT ts, author, body FROM incident_notes WHERE incident_id=? ORDER BY ts", (iid,)),
                "audit": agent.db.query("SELECT ts, actor, action, result, detail FROM actions_audit WHERE target=? ORDER BY ts", (iid,))}
        agent.db.audit("user", "export_incident", iid)
        return JSONResponse(data, headers={"Content-Disposition": f"attachment; filename={iid}.json"})

    @app.post(P + "/alerts/{iid}/acknowledge")
    def ack(iid: str):
        if not agent.db.one("SELECT 1 FROM incidents WHERE incident_id=?", (iid,)):
            raise HTTPException(404, "incident not found")
        agent.db.execute("UPDATE incidents SET status='acknowledged' WHERE incident_id=?", (iid,))
        agent.db.audit("user", "acknowledge", iid)
        return {"ok": True}

    @app.post(P + "/alerts/{iid}/dismiss")
    def dismiss(iid: str, req: DismissReq):
        if not agent.db.one("SELECT 1 FROM incidents WHERE incident_id=?", (iid,)):
            raise HTTPException(404, "incident not found")
        agent.db.execute("UPDATE incidents SET status='dismissed', decision='dismissed', decision_reason=?, closed_at=? WHERE incident_id=?",
                         (req.reason, time.time(), iid))
        agent.db.audit("user", "dismiss", iid, "ok", req.reason)
        return {"ok": True}

    # ---- models / scan / terminal --------------------------------------------------------------
    @app.get(P + "/models")
    def models():
        return {"installed": agent.db.query("SELECT * FROM model_registry"), "active": agent.model.info if agent.model.loaded else None,
                "validated": agent.model.validated, "warning": agent.model.warning, "extractor_schema": agent.model._extractor_schema(),
                "extractor": agent.model.extractor_status(),
                "note": "A model counts as E1 evidence only when its card says validated. Core detection runs deterministic OS rules E2–E6."}

    _ML_UNAVAILABLE = {"available": False, "reason": "ML training module moved to optional/"}

    @app.get(P + "/training/datasets")
    def training_datasets():
        if agent.trainer is None:
            return _ML_UNAVAILABLE
        return agent.trainer.datasets()

    @app.get(P + "/training/status")
    def training_status():
        if agent.trainer is None:
            return _ML_UNAVAILABLE
        return agent.trainer.status()

    @app.post(P + "/training/start")
    def training_start(req: TrainReq):
        if agent.trainer is None:
            return _ML_UNAVAILABLE
        return agent.trainer.start(req.source, req.max_rows)

    @app.post(P + "/training/cancel")
    def training_cancel():
        if agent.trainer is None:
            return _ML_UNAVAILABLE
        return agent.trainer.cancel()

    @app.post(P + "/models/reload")
    def models_reload():
        agent.reload_model()
        return {"loaded": agent.model.loaded, "validated": agent.model.validated, "warning": agent.model.warning}

    @app.post(P + "/scan")
    def scan(req: ScanReq):
        res = pe.scan_file(req.path, agent.model)
        agent.db.audit("user", "scan", req.path[:200])
        return res

    @app.post(P + "/terminal")
    def terminal(req: TermReq):
        return commands.run(agent, req.line)

    # ---- settings / allowlist / actions -----------------------------------------------------------
    @app.get(P + "/settings/privacy")
    def get_privacy():
        return agent.privacy

    @app.put(P + "/settings/privacy")
    def put_privacy(req: PrivacyUpdate):
        agent.privacy.update({k: v for k, v in req.model_dump().items() if v is not None})
        agent.apply_privacy()                         # persists + starts/stops collectors immediately
        agent.db.audit("user", "privacy_update", "", "ok", json.dumps(req.model_dump(exclude_none=True)))
        return agent.privacy

    @app.get(P + "/allowlist")
    def allow_list():
        return {"items": agent.db.query("SELECT * FROM allowlist ORDER BY added_at DESC")}

    @app.post(P + "/allowlist")
    def allow_add(req: AllowReq):
        agent.db.execute("INSERT OR REPLACE INTO allowlist VALUES(?,?,?,?)", (req.kind, req.value.lower() if req.kind == "sha256" else req.value, req.reason, time.time()))
        agent.db.audit("user", "allowlist_add", f"{req.kind}:{req.value[:80]}", "ok", req.reason)
        return {"ok": True}

    @app.delete(P + "/allowlist")
    def allow_del(kind: str, value: str):
        agent.db.execute("DELETE FROM allowlist WHERE kind=? AND value=?", (kind, value))
        agent.db.audit("user", "allowlist_remove", f"{kind}:{value[:80]}")
        return {"ok": True}

    @app.post(P + "/actions/preview")
    def preview(req: PreviewReq):
        tgt = req.target
        pi = agent.procs.get(tgt) or next((p for p in agent.procs.values() if str(p["pid"]) == tgt), None)
        impact = {"terminate": "Would end the process and its unsaved work; child processes may be orphaned.",
                  "quarantine": "Would move the executable to a protected folder and block execution.",
                  "suspend": "Would freeze the process until you resume it.", "resume": "Would let a suspended process continue.",
                  "block": "Would add a firewall rule for the process' remote endpoint."}[req.action]
        agent.db.audit("user", "action_preview", f"{req.action}:{tgt[:80]}", "preview-only")
        return {"preview_only": True, "executed": False, "action": req.action,
                "target": {"name": pi["name"], "pid": pi["pid"], "exe": pi.get("exe")} if pi else {"raw": tgt},
                "impact": impact, "reason": "Preview only. Use the action button and type the process name to confirm."}

    @app.post(P + "/actions/execute")
    def execute_action(req: ExecReq):
        from . import response
        try:
            return response.execute(agent, req.action, req.target, req.confirm_name)
        except response.ActionError as e:
            agent.db.audit("user", f"response_{req.action}", req.target[:80], "refused", str(e)[:200])
            raise HTTPException(400, str(e))

    @app.get(P + "/quarantine")
    def quarantine():
        from . import response
        return {"items": response.quarantine_list()}

    @app.post(P + "/quarantine/{qid}/restore")
    def quarantine_restore(qid: str):
        from . import response
        try:
            return response.restore(agent, qid)
        except response.ActionError as e:
            raise HTTPException(400, str(e))

    # ---- simulation / export / wipe / audit ------------------------------------------------------------
    @app.get(P + "/simulate")
    def sim_list():
        return {"scenarios": simulate.SCENARIOS}

    @app.post(P + "/simulate/{name}")
    def sim_run(name: str):
        try:
            return simulate.run(agent, name)
        except KeyError:
            raise HTTPException(404, "unknown scenario")

    @app.delete(P + "/simulate")
    def sim_clear():
        simulate.clear(agent)
        return {"ok": True}

    @app.get(P + "/export")
    def export():
        data = {"exported_at": time.time(), "host": agent.hostname, "incidents": [_inc_row(r) for r in agent.db.query("SELECT * FROM incidents")],
                "detections": agent.db.query("SELECT * FROM detections"),
                "events": agent.db.query("SELECT * FROM events ORDER BY ts DESC LIMIT 5000")}
        return JSONResponse(data, headers={"Content-Disposition": "attachment; filename=guardian_export.json"})

    @app.delete(P + "/data")
    def wipe(req: WipeReq):
        if req.confirm != "DELETE":
            raise HTTPException(400, "type DELETE to confirm")
        agent.db.wipe_telemetry()
        agent.db.audit("user", "wipe_local_data")
        return {"ok": True}

    @app.get(P + "/audit")
    def audit(limit: int = Query(100, ge=1, le=500)):
        return {"items": agent.db.query("SELECT * FROM actions_audit ORDER BY action_id DESC LIMIT ?", (limit,)),
                "chain_ok": agent.db.verify_audit_chain(), "auth_failures": auth_failures[-20:]}

    # ---- websocket (token as first message; headers unavailable in browsers) ---------------------------
    @app.websocket(P + "/ws")
    async def ws(sock: WebSocket):
        if not host_ok(sock.headers.get("host")) or not origin_ok(sock.headers.get("origin")):
            await sock.close(code=4403); return
        await sock.accept()
        try:
            first = json.loads(await asyncio.wait_for(sock.receive_text(), 5))
        except Exception:
            await sock.close(code=4401); return
        if not token_ok(first.get("token")):
            await sock.close(code=4401); return
        loop = asyncio.get_running_loop()
        q: asyncio.Queue = asyncio.Queue(maxsize=200)

        def cb(msg):
            try:
                loop.call_soon_threadsafe(lambda: q.put_nowait(msg) if not q.full() else None)
            except RuntimeError:
                pass
        agent.subscribers.append(cb)
        try:
            await sock.send_json({"type": "hello", "data": {"version": config.VERSION}})
            last_events = 0.0
            while True:
                msg = await q.get()
                if msg["type"] == "events":              # throttle: UI refreshes only relevant parts (spec 4.1)
                    if time.time() - last_events < 0.5:
                        continue
                    last_events = time.time()
                await sock.send_json(msg)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            if cb in agent.subscribers:
                agent.subscribers.remove(cb)

    # ---- static UI (no token needed for the shell itself) --------------------------------------------------------
    app.mount("/", StaticFiles(directory=str(config.UI_DIR), html=True), name="ui")
    return app
