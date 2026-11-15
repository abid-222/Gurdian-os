"""Entry point: python -m guardian.main  (starts agent + loopback API + opens the desktop shell)."""
from __future__ import annotations
import argparse, json, os, secrets, socket, subprocess, sys, threading, time, webbrowser, logging
import uvicorn
from . import config
from .agent import Agent
from .api import create_app

EDGE_PATHS = [r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
              r"C:\Program Files\Google\Chrome\Application\chrome.exe", r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def lock_down(path):
    """Best effort: per-user-only ACL for the runtime file holding the session token."""
    try:
        if config.IS_WINDOWS:
            user = os.environ.get("USERNAME", "")
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"], capture_output=True, creationflags=0x08000000)
        else:
            os.chmod(path, 0o600)
    except Exception:
        pass


def open_ui(url: str):
    if config.IS_WINDOWS:
        for exe in EDGE_PATHS:
            if os.path.exists(exe):          # chromeless "app" window = desktop-app feel, no extra dependencies
                subprocess.Popen([exe, f"--app={url}", "--window-size=1500,920"])
                return
    webbrowser.open(url)


def main():
    ap = argparse.ArgumentParser(description="Smart OS Guardian")
    ap.add_argument("--port", type=int, default=int(os.environ.get("GUARDIAN_PORT", 0)) or 0)
    ap.add_argument("--no-ui", action="store_true", help="do not open the window")
    ap.add_argument("--print-token", action="store_true")
    args = ap.parse_args()
    from logging.handlers import RotatingFileHandler
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger(); root.setLevel(logging.INFO)
    fh = RotatingFileHandler(config.log_dir() / "guardian.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"); fh.setFormatter(fmt); root.addHandler(fh)
    sh = logging.StreamHandler(); sh.setFormatter(fmt); root.addHandler(sh)
    port = args.port or free_port()
    token = secrets.token_urlsafe(32)               # 256-bit per-session token, rotated at each start
    agent = Agent()
    app = create_app(agent, token, port)
    rt = config.runtime_dir() / "runtime.json"
    rt.write_text(json.dumps({"port": port, "token": token, "pid": os.getpid(), "started": time.time()}))
    lock_down(rt)
    url = f"http://127.0.0.1:{port}/#t={token}"
    print(f"\n  Smart OS Guardian {config.VERSION}\n  UI:  http://127.0.0.1:{port}/   (loopback only)\n  Data: {agent.db.path}\n  Log:  {config.log_dir() / 'guardian.log'}")
    logging.getLogger("guardian").info("started v%s port=%s admin=%s model=%s", config.VERSION, port, agent.caps["admin"], agent.model.loaded)
    if agent.db.recovery_notice:
        print("  !! " + agent.db.recovery_notice)
    if args.print_token:
        print(f"  Open: {url}")
    print("  Sources:", ", ".join(f"{k}={v['status']}" for k, v in agent.caps["sources"].items()))
    if not agent.caps["admin"] and config.IS_WINDOWS:
        print("  Note: not elevated - Security log and some process details are limited (shown as 'degraded' in the UI).")
    if not args.no_ui:
        threading.Timer(1.2, open_ui, args=(url,)).start()
    try:
        uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
    finally:
        agent.stop()
        try:
            rt.unlink()
        except OSError:
            pass


if __name__ == "__main__":
    main()
