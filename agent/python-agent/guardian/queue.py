"""Bounded in-memory event queue with backpressure, priority load shedding and per-source drop counters."""
from __future__ import annotations
import threading, json, collections
from . import config


class EventQueue:
    def __init__(self, max_events=config.QUEUE_MAX_EVENTS, max_bytes=config.QUEUE_MAX_BYTES):
        self.max_events, self.max_bytes = max_events, max_bytes
        self.q: collections.deque = collections.deque()
        self.bytes = 0
        self.lock = threading.Lock()
        self.cv = threading.Condition(self.lock)
        self.generated = 0
        self.dropped = 0
        self.dropped_by_source: dict[str, int] = collections.defaultdict(int)
        self.rejected_schema = 0

    @property
    def fill(self) -> float:
        return max(len(self.q) / self.max_events, self.bytes / self.max_bytes)

    def state(self) -> str:
        f = self.fill
        return "shedding" if f >= config.SHED_RATIO else "warning" if f >= config.WARN_RATIO else "ok"

    def put(self, event: dict) -> bool:
        size = len(json.dumps(event, default=str))
        prio = config.PRIORITY.get(event["event_type"], 3)
        with self.cv:
            self.generated += 1
            f = self.fill
            if f >= 1.0 or (f >= config.SHED_RATIO and prio >= 3):     # shed lowest-priority first
                self.dropped += 1
                self.dropped_by_source[event["source"]] += 1
                return False
            self.q.append((event, size))
            self.bytes += size
            self.cv.notify()
            return True

    def drain(self, max_n=config.BATCH_EVENTS, timeout=config.BATCH_SECONDS) -> list[dict]:
        with self.cv:
            if not self.q:
                self.cv.wait(timeout)
            out = []
            while self.q and len(out) < max_n:
                e, size = self.q.popleft()
                self.bytes = max(0, self.bytes - size)
                out.append(e)
            return out

    def stats(self) -> dict:
        return {"depth": len(self.q), "bytes": self.bytes, "fill_pct": round(self.fill * 100, 1), "state": self.state(),
                "generated": self.generated, "dropped": self.dropped,
                "drop_rate_pct": round(100 * self.dropped / self.generated, 4) if self.generated else 0.0,
                "dropped_by_source": dict(self.dropped_by_source)}
