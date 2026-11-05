"""SQLite job log. One row per job; the evolving job state is a JSON document."""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    created_at REAL NOT NULL,
    ip TEXT NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL,
    state TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS jobs_created ON jobs(created_at);
CREATE INDEX IF NOT EXISTS jobs_ip ON jobs(ip, created_at);
"""


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA)
        self._lock = threading.Lock()

    def create(self, job_id: str, ip: str, kind: str, state: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO jobs(id, created_at, ip, kind, status, state) VALUES (?,?,?,?,?,?)",
                (job_id, state.get("created_at", time.time()), ip, kind, state["status"], json.dumps(state)),
            )

    def save(self, state: dict) -> None:
        with self._lock:
            self._db.execute("UPDATE jobs SET status=?, state=? WHERE id=?",
                             (state["status"], json.dumps(state), state["id"]))

    def get(self, job_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT state FROM jobs WHERE id=?", (job_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def recent(self, limit: int = 12) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT state FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def count_active(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0]

    def count_since(self, since: float, ip: str | None = None) -> int:
        with self._lock:
            if ip is None:
                return self._db.execute("SELECT COUNT(*) FROM jobs WHERE created_at>=?", (since,)).fetchone()[0]
            return self._db.execute("SELECT COUNT(*) FROM jobs WHERE created_at>=? AND ip=?", (since, ip)).fetchone()[0]

    def queued_ids(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._db.execute(
                "SELECT id FROM jobs WHERE status='queued' ORDER BY created_at").fetchall()]

    def mark_interrupted(self) -> int:
        """Jobs that were running when the process died cannot be resumed."""
        n = 0
        for job_id in [r[0] for r in self._db.execute("SELECT id FROM jobs WHERE status='running'").fetchall()]:
            state = self.get(job_id)
            if state:
                state["status"] = "failed"
                state["error"] = "interrupted by a server restart"
                state["finished_at"] = time.time()
                self.save(state)
                n += 1
        return n
