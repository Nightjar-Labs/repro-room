"""One-at-a-time job queue with abuse limits for a public URL."""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from .config import Settings
from .pipeline import new_job_id, new_state
from .store import Store

log = logging.getLogger(__name__)


class LimitError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class JobQueue:
    def __init__(self, settings: Settings, store: Store, process: Callable[[str], None]):
        self.settings = settings
        self.store = store
        self.process = process
        self._q: queue.Queue[str | None] = queue.Queue()
        self._lock = threading.Lock()
        self._order: list[str] = []
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        for job_id in self.store.queued_ids():
            self._enqueue(job_id)
        self._thread = threading.Thread(target=self._loop, name="reproroom-worker", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5) -> None:
        self._q.put(None)
        if self._thread:
            self._thread.join(timeout)

    def _enqueue(self, job_id: str) -> None:
        with self._lock:
            self._order.append(job_id)
        self._q.put(job_id)

    def position(self, job_id: str) -> int | None:
        """0 = running now, n = n jobs ahead of it; None if not queued."""
        with self._lock:
            return self._order.index(job_id) if job_id in self._order else None

    def check_limits(self, ip: str) -> None:
        s = self.settings
        if self.store.count_active() >= s.max_queue:
            raise LimitError(503, f"The queue is full ({s.max_queue} jobs). Please try again in a few minutes.")
        if self.store.count_since(time.time() - s.rate_limit_window, ip) >= s.rate_limit_per_ip:
            raise LimitError(429, f"Rate limit: at most {s.rate_limit_per_ip} jobs per {s.rate_limit_window // 60} minutes per address.")
        midnight = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        if self.store.count_since(midnight) >= s.daily_job_cap:
            raise LimitError(429, f"The public demo's daily cap ({s.daily_job_cap} jobs) is reached. It resets at 00:00 UTC.")

    def submit(self, kind: str, source: str, ip: str, *, title: str = "", text: str = "") -> str:
        with self._lock:  # limit check and insert are atomic w.r.t. other submissions
            self.check_limits(ip)
            job_id = new_job_id()
            self.store.create(job_id, ip, kind, new_state(job_id, kind, source, title=title, text=text))
        self._enqueue(job_id)
        return job_id

    def _loop(self) -> None:
        while True:
            job_id = self._q.get()
            if job_id is None:
                return
            try:
                self.process(job_id)
            except Exception:  # pipeline already records failures; never let the worker die
                log.exception("worker: job %s raised", job_id)
            finally:
                with self._lock:
                    if job_id in self._order:
                        self._order.remove(job_id)
