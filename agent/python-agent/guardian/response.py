"""User-initiated response actions: terminate, suspend, resume, quarantine, restore.

Never automatic: every action needs an explicit request with the process name typed as confirmation, is verified against the live process
identity (pid + start time, so a reused PID is never hit), refuses protected targets, and is written to the audit log."""
from __future__ import annotations
import json, os, pathlib, shutil, time, uuid
import psutil
from . import config

PROTECTED = {"system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe",
             "fontdrvhost.exe", "dwm.exe", "memcompression", "secure system", "init", "systemd", "launchd", "kthreadd"}
OS_DIRS = ("c:\\windows\\", "/usr/", "/bin/", "/sbin/", "/lib/", "/system/", "/library/")


class ActionError(Exception):
    pass


def qdir() -> pathlib.Path:
    d = config.data_dir() / "quarantine"; d.mkdir(parents=True, exist_ok=True)
    return d


def _resolve(agent, target: str) -> tuple[dict, psutil.Process]:
    pi = agent.procs.get(target) or next((p for p in agent.procs.values() if str(p["pid"]) == target), None)
    if not pi:
        raise ActionError("process not found (it may have exited)")
    if pi.get("simulated"):
        raise ActionError("this is a synthetic (SIM) process: nothing real to act on")
    try:
        proc = psutil.Process(pi["pid"])
        if abs(proc.create_time() - pi["start_ts"]) > 2.0:
            raise ActionError("the PID now belongs to a different process (original exited): refusing")
    except psutil.NoSuchProcess:
        raise ActionError("process already exited")
    return pi, proc


def _guard(agent, pi: dict, action: str):
    own = {os.getpid(), os.getppid()}
    if pi["pid"] in own or pi["pid"] <= 4 or pi["name"] in PROTECTED:
        raise ActionError(f"{pi['name']} is a protected system/guardian process: refused")
    exe = (pi.get("exe") or "").lower().replace("/", "\\") if config.IS_WINDOWS else (pi.get("exe") or "").lower()
    if action == "quarantine" and any(exe.startswith(d) for d in OS_DIRS):
        raise ActionError("files in operating-system folders are never quarantined")


def execute(agent, action: str, target: str, confirm_name: str) -> dict:
    if not agent.privacy.get("response_actions_enabled", True):
        raise ActionError("response actions are switched off in Settings")
    pi, proc = _resolve(agent, target)
    _guard(agent, pi, action)
    if (confirm_name or "").strip().lower() != pi["name"].lower():
        raise ActionError(f"confirmation text must be the process name: {pi['name']}")
    detail, ok = "", True
    try:
        if action == "terminate":
            kids = proc.children(recursive=False)
            proc.terminate()
            try:
                proc.wait(3)
            except psutil.TimeoutExpired:
                proc.kill(); proc.wait(3)
            detail = f"ended {pi['name']} (pid {pi['pid']}); {len(kids)} child process(es) left running"
        elif action == "suspend":
            proc.suspend(); detail = f"suspended {pi['name']} (pid {pi['pid']}); resume restores it"
        elif action == "resume":
            proc.resume(); detail = f"resumed {pi['name']}"
        elif action == "quarantine":
            exe = pi.get("exe")
            if not exe or not os.path.isfile(exe):
                raise ActionError("executable path unknown or file missing")
            try:
                proc.terminate(); proc.wait(3)
            except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                try:
                    proc.kill()
                except psutil.NoSuchProcess:
                    pass
            qid = uuid.uuid4().hex[:12]
            dest = qdir() / f"{qid}.quarantined"
            shutil.move(exe, dest)
            (qdir() / f"{qid}.json").write_text(json.dumps({"id": qid, "original_path": exe, "name": pi["name"], "sha256": pi.get("sha256"), "ts": time.time()}))
            detail = f"process ended and file moved to quarantine ({qid}); restore from Settings"
        else:
            raise ActionError("unknown action")
    except ActionError:
        raise
    except psutil.AccessDenied:
        ok = False; detail = "access denied: run Guardian as administrator (run_admin.bat) to act on this process"
    except psutil.NoSuchProcess:
        ok = False; detail = "process already exited"
    except OSError as e:
        ok = False; detail = f"{type(e).__name__}: {e}"
    agent.db.audit("user", f"response_{action}", f"{pi['name']}:{pi['pid']}", "ok" if ok else "failed", detail[:200])
    agent.emit("guardian", "response_action", ts=time.time(), attributes={"action": action, "target": pi["name"], "pid": pi["pid"], "ok": ok, "detail": detail})
    return {"ok": ok, "executed": ok, "action": action, "detail": detail}


def quarantine_list() -> list[dict]:
    out = []
    for f in sorted(qdir().glob("*.json")):
        try:
            out.append(json.loads(f.read_text()))
        except Exception:
            pass
    return out


def restore(agent, qid: str) -> dict:
    meta_f, blob = qdir() / f"{qid}.json", qdir() / f"{qid}.quarantined"
    if not (qid.isalnum() and meta_f.exists() and blob.exists()):
        raise ActionError("quarantine item not found")
    meta = json.loads(meta_f.read_text())
    dest = pathlib.Path(meta["original_path"])
    if dest.exists():
        raise ActionError(f"a file already exists at {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(blob, dest); meta_f.unlink()
    agent.db.audit("user", "response_restore", meta["name"], "ok", str(dest)[:200])
    return {"ok": True, "restored_to": str(dest)}
