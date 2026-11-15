"""Low-priority hash/signer enrichment. Files are read, never executed."""
from __future__ import annotations
import hashlib, os, queue, subprocess, threading, json
from . import config

MAX_HASH_BYTES = 128 * 1024 * 1024


def sha256_file(path: str) -> str | None:
    try:
        if os.path.getsize(path) > MAX_HASH_BYTES:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def authenticode_status(path: str) -> str:
    """'signed' | 'unsigned' | 'invalid' | 'unknown'. Windows only, via PowerShell (no code execution of the target)."""
    if not config.IS_WINDOWS:
        return "unknown"
    try:
        ps = f"(Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39)*2)}').Status"
        out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                             capture_output=True, text=True, timeout=15,
                             creationflags=0x08000000).stdout.strip()
        if out == "Valid":
            return "signed"
        if out == "NotSigned":
            return "unsigned"
        return "invalid" if out else "unknown"
    except Exception:
        return "unknown"


class Enricher:
    def __init__(self):
        self.cache: dict[str, dict] = {}
        self.q: queue.Queue = queue.Queue(maxsize=2000)
        self.pending: set[str] = set()
        self.running = True
        self.on_done = None
        self.thread = threading.Thread(target=self._run, name="enricher", daemon=True)
        self.thread.start()

    def request(self, path: str | None, want_signer: bool = True):
        if not path or path in self.cache or path in self.pending:
            return
        try:
            self.q.put_nowait((path, want_signer))
            self.pending.add(path)
        except queue.Full:
            pass

    def get(self, path: str | None) -> dict:
        return self.cache.get(path or "", {})

    def _run(self):
        while self.running:
            try:
                path, want_signer = self.q.get(timeout=1)
            except queue.Empty:
                continue
            info = {"sha256": sha256_file(path), "signer": authenticode_status(path) if want_signer else "unknown"}
            self.cache[path] = info
            self.pending.discard(path)
            if self.on_done:
                try:
                    self.on_done(path, info)
                except Exception:
                    pass
            self.q.task_done()
