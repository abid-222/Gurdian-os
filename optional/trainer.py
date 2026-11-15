"""One-button model training (runs ai/malware-pe/train.py as a background child process of the agent).

Flow: check/install training components -> unpack + read datasets/ -> vectorise -> train -> calibrate -> package -> hot-reload the model.
The child runs at low priority so the PC stays usable; it only reads files in datasets/ and never executes any sample."""
from __future__ import annotations
import collections, importlib.util, json, logging, os, subprocess, sys, threading, time
from . import config

log = logging.getLogger("guardian.trainer")
TRAIN = config.ROOT / "ai" / "malware-pe" / "train.py"
REQS = config.ROOT / "requirements-model.txt"
NEEDED = {"lightgbm": "lightgbm", "sklearn": "scikit-learn", "numpy": "numpy", "pefile": "pefile", "signify": "signify"}


def missing_components() -> list[str]:
    return [pip for mod, pip in NEEDED.items() if importlib.util.find_spec(mod) is None]


def _helper():
    d = str(config.ROOT / "ai" / "malware-pe")
    if d not in sys.path:
        sys.path.insert(0, d)
    import datasets  # type: ignore
    return datasets


class Trainer:
    def __init__(self, agent):
        self.agent = agent
        self.lock = threading.Lock()
        self.proc: subprocess.Popen | None = None
        self.state = {"running": False, "progress": 0, "message": "idle", "ok": None, "error": None, "started": None, "finished": None}
        self.lines: collections.deque[str] = collections.deque(maxlen=300)

    # ---------------------------------------------------------------- info
    def datasets(self) -> dict:
        ds = _helper()
        s = ds.public(ds.scan(ds.DATASETS, unpack=False))
        s["datasets_dir"] = str(ds.DATASETS)
        s["missing_components"] = missing_components()
        s["max_rows_default"] = 150000
        return s

    def status(self) -> dict:
        return {**self.state, "log": list(self.lines)[-60:], "missing_components": missing_components()}

    # ---------------------------------------------------------------- control
    def start(self, source: str = "auto", max_rows: int = 150000) -> dict:
        with self.lock:
            if self.state["running"]:
                return {"ok": False, "error": "training is already running"}
            self.lines.clear()
            self.state.update(running=True, progress=0, message="starting", ok=None, error=None, started=time.time(), finished=None)
        threading.Thread(target=self._run, args=(source, max(1000, int(max_rows))), daemon=True, name="trainer").start()
        return {"ok": True}

    def cancel(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.lines.append("cancelled by user")
        return {"ok": True}

    # ---------------------------------------------------------------- worker
    def _say(self, line: str):
        line = line.rstrip()
        if not line:
            return
        if line.startswith("PROGRESS "):
            parts = line.split(" ", 2)
            try:
                self.state["progress"] = max(self.state["progress"], int(parts[1]))
            except (ValueError, IndexError):
                pass
            self.state["message"] = parts[2] if len(parts) > 2 else ""
            return
        self.lines.append(line[:300])

    def _stream(self, cmd: list[str]) -> int:
        flags = 0x00004000 | 0x08000000 if config.IS_WINDOWS else 0          # BELOW_NORMAL_PRIORITY | CREATE_NO_WINDOW
        env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
        self.proc = subprocess.Popen(cmd, cwd=str(config.ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                     env=env, creationflags=flags, preexec_fn=(lambda: os.nice(10)) if not config.IS_WINDOWS else None)
        for line in self.proc.stdout:
            self._say(line)
        return self.proc.wait()

    def _finish(self, ok: bool, error: str | None = None):
        self.state.update(running=False, ok=ok, error=error, finished=time.time(), progress=100 if ok else self.state["progress"],
                          message="model trained and loaded" if ok else (error or "failed"))
        self.agent.db.audit("user", "training_finished", "malware-pe", "ok" if ok else "failed", (error or "")[:120])

    def _run(self, source: str, max_rows: int):
        try:
            self.agent.db.audit("user", "training_start", "malware-pe", "ok", f"source={source} max_rows={max_rows}")
            miss = missing_components()
            if miss:
                self.state["message"] = "installing training components: " + ", ".join(miss)
                self._say(f"pip install -r {REQS.name}  (internet needed once)")
                rc = self._stream([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "-r", str(REQS)])
                if rc != 0 or missing_components():
                    return self._finish(False, "could not install the training components (check internet / Python 3.10-3.12). See log.")
            self.state["progress"] = 1
            rc = self._stream([sys.executable, str(TRAIN), "--source", source, "--max-rows", str(max_rows)])
            if rc != 0:
                tail = [l for l in self.lines if l.strip()][-1:] or ["training failed"]
                return self._finish(False, tail[0])
            self.agent.reload_model()
            m = self.agent.model
            if m.loaded and not m.validated:
                self.lines.append("Model installed but did NOT pass the quality gate: scores are shown, never used as evidence.")
            self._finish(True)
        except Exception as e:
            log.exception("training failed")
            self._finish(False, f"{type(e).__name__}: {e}")
