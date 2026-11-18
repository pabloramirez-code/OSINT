import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import datetime, timedelta

from reconmap.models import utcnow

MISSING = object()


class Cache:
    """Caché persistente en SQLite: sobrevive a reinicios y se comparte entre web y CLI."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        lock: threading.Lock,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self._conn = conn
        self._lock = lock
        self._clock = clock
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS cache "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at TEXT NOT NULL)"
            )

    def get(self, key: str) -> object:
        with self._lock:
            row = self._conn.execute(
                "SELECT value, expires_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if row is None or datetime.fromisoformat(row[1]) <= self._clock():
            return MISSING
        value: object = json.loads(row[0])
        return value

    def set(self, key: str, value: object, ttl: timedelta) -> None:
        expires_at = (self._clock() + ttl).isoformat()
        with self._lock:
            self._conn.execute(
                "INSERT INTO cache (key, value, expires_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "expires_at = excluded.expires_at",
                (key, json.dumps(value), expires_at),
            )
