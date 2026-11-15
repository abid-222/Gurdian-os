from __future__ import annotations
import threading, time, traceback


class Collector(threading.Thread):
    """Event-driven where possible; otherwise a low-frequency diff loop. Each tick records a heartbeat."""
    name_id = "collector"
    interval = 2.0

    def __init__(self, agent):
        super().__init__(name=self.name_id, daemon=True)
        self.agent = agent
        self.stop_flag = threading.Event()
        self.last_beat = 0.0
        self.errors = 0
        self.last_error: str | None = None

    def setup(self):  # optional baseline
        pass

    def tick(self):
        raise NotImplementedError

    def run(self):
        try:
            self.setup()
        except Exception as e:
            self.errors += 1; self.last_error = repr(e)
        while not self.stop_flag.is_set():
            if not self.agent.paused:
                try:
                    self.tick()
                except Exception as e:
                    self.errors += 1
                    self.last_error = "".join(traceback.format_exception_only(type(e), e)).strip()
            self.last_beat = time.time()
            self.stop_flag.wait(self.interval)

    def stop(self):
        self.stop_flag.set()

    def health(self) -> dict:
        age = time.time() - self.last_beat if self.last_beat else None
        status = "ok" if age is not None and age < self.interval * 4 + 2 else "stalled"
        return {"name": self.name_id, "status": status, "errors": self.errors, "last_error": self.last_error,
                "last_beat_age_s": round(age, 1) if age is not None else None}
