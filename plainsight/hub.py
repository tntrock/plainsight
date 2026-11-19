"""Hub: collects findings and fans them out to dashboard subscribers."""
from __future__ import annotations

import queue
import threading
from collections import deque

from .events import Finding, Stats
from .redact import redact


class Hub:
    MAX_DEDUP = 100_000

    def __init__(self, show_secrets: bool = False, max_items: int = 5000) -> None:
        self.show_secrets = show_secrets
        self.stats = Stats()
        self._lock = threading.Lock()
        self._items: deque[dict] = deque(maxlen=max_items)
        self._seen: set[str] = set()
        self._subs: set[queue.Queue] = set()

    def publish(self, finding: Finding) -> bool:
        data = finding.to_dict() if self.show_secrets else redact(finding)
        with self._lock:
            if finding.dedup:
                if finding.dedup in self._seen:
                    return False
                if len(self._seen) >= self.MAX_DEDUP:
                    self._seen.clear()
                self._seen.add(finding.dedup)
            self._items.append(data)
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(data)
            except queue.Full:
                pass  # a stalled browser tab must not block capture
        return True

    def subscribe(self) -> tuple[queue.Queue, list[dict]]:
        """Returns a queue of new findings plus everything seen so far."""
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            self._subs.add(q)
            return q, list(self._items)

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            self._subs.discard(q)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._items)
