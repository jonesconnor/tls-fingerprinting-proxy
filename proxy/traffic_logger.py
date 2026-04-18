"""
traffic_logger.py — SQLite-backed traffic log for the proxy.

One record per classified connection. Separate from the NDJSON fingerprint
log: the NDJSON log is for research/capture, this log is for the /stats
dashboard. WAL mode is required because the backend reads this file from a
separate process while the proxy is writing to it.
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone

TRAFFIC_DB_PATH = os.getenv("TRAFFIC_DB_PATH", "")

_log = logging.getLogger("proxy")

_DDL = """
CREATE TABLE IF NOT EXISTS traffic_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    ja4         TEXT    NOT NULL,
    path        TEXT,
    client_type TEXT    NOT NULL,
    detail      TEXT,
    confidence  TEXT,
    match_type  TEXT
);
CREATE INDEX IF NOT EXISTS idx_ts          ON traffic_log (ts);
CREATE INDEX IF NOT EXISTS idx_client_type ON traffic_log (client_type);
CREATE INDEX IF NOT EXISTS idx_match_type  ON traffic_log (match_type);
"""


class TrafficLogger:
    """Thread-safe SQLite writer. Call open() once at startup."""

    def __init__(self) -> None:
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    def open(self) -> None:
        if not TRAFFIC_DB_PATH:
            _log.info("TRAFFIC_DB_PATH not set — traffic log disabled")
            return
        try:
            self._conn = sqlite3.connect(TRAFFIC_DB_PATH, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(_DDL)
            self._conn.commit()
            _log.info(f"Traffic log: {TRAFFIC_DB_PATH}")
        except Exception as exc:
            _log.warning(f"TrafficLogger: could not open {TRAFFIC_DB_PATH}: {exc}")
            self._conn = None

    def record(
        self,
        *,
        ja4: str,
        path: str,
        client_type: str,
        detail: str,
        confidence: str,
        match_type: str,
    ) -> None:
        if self._conn is None:
            return
        ts = datetime.now(timezone.utc).isoformat()
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT INTO traffic_log"
                    " (ts, ja4, path, client_type, detail, confidence, match_type)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (ts, ja4, path, client_type, detail, confidence, match_type),
                )
                self._conn.commit()
            except Exception as exc:
                _log.warning(f"TrafficLogger: write failed: {exc}")
