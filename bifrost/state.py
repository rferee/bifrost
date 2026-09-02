"""Persistent sync state.

This is what makes deletion safe. Comparing two sides tells you a file exists in
one place and not the other; it cannot tell you whether it was deleted over
there or created over here. The `synced` table is the third point of reference
that answers that.

State is keyed on the *remote folder* (scope), not the rule, so a pull rule and
a push rule aimed at the same folder share one view of what has already been
transferred. Without that, the push rule would re-upload everything the pull
rule just wrote.

Losing this database is safe: an empty owned-set degrades bifrost to
additive-only and re-downloads everything, which is the correct failure
direction.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS synced (
    scope        TEXT    NOT NULL,
    path         TEXT    NOT NULL,
    etag         TEXT,
    remote_mtime INTEGER,
    remote_size  INTEGER,
    local_mtime  INTEGER,
    local_size   INTEGER,
    sha256       TEXT,
    pulled       INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL,
    PRIMARY KEY (scope, path)
);

CREATE TABLE IF NOT EXISTS quarantine (
    sha256 TEXT PRIMARY KEY,
    scope  TEXT,
    path   TEXT,
    reason TEXT,
    at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS breaker (
    name   TEXT PRIMARY KEY,
    reason TEXT,
    at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS flags (
    name  TEXT PRIMARY KEY,
    value TEXT,
    at    INTEGER NOT NULL
);
"""


@dataclass(frozen=True)
class SyncedRow:
    path: str
    etag: str | None
    remote_mtime: int | None
    remote_size: int | None
    local_mtime: int | None
    local_size: int | None
    sha256: str | None
    pulled: bool


class State:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    # -- synced set ---------------------------------------------------------

    def entries(self, scope: str) -> dict[str, SyncedRow]:
        rows = self._db.execute(
            "SELECT path, etag, remote_mtime, remote_size, local_mtime, local_size, sha256, pulled "
            "FROM synced WHERE scope = ?",
            (scope,),
        ).fetchall()
        return {
            row["path"]: SyncedRow(
                path=row["path"],
                etag=row["etag"],
                remote_mtime=row["remote_mtime"],
                remote_size=row["remote_size"],
                local_mtime=row["local_mtime"],
                local_size=row["local_size"],
                sha256=row["sha256"],
                pulled=bool(row["pulled"]),
            )
            for row in rows
        }

    def record(
        self,
        scope: str,
        path: str,
        *,
        etag: str | None,
        remote_mtime: int | None,
        remote_size: int | None,
        local_mtime: int | None,
        local_size: int | None,
        sha256: str | None,
        pulled: bool,
    ) -> None:
        self._db.execute(
            "INSERT INTO synced (scope, path, etag, remote_mtime, remote_size, local_mtime, "
            "local_size, sha256, pulled, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scope, path) DO UPDATE SET etag=excluded.etag, "
            "remote_mtime=excluded.remote_mtime, remote_size=excluded.remote_size, "
            "local_mtime=excluded.local_mtime, local_size=excluded.local_size, "
            "sha256=excluded.sha256, pulled=MAX(synced.pulled, excluded.pulled), "
            "updated_at=excluded.updated_at",
            (
                scope,
                path,
                etag,
                remote_mtime,
                remote_size,
                local_mtime,
                local_size,
                sha256,
                int(pulled),
                int(time.time()),
            ),
        )

    def forget(self, scope: str, path: str) -> None:
        self._db.execute("DELETE FROM synced WHERE scope = ? AND path = ?", (scope, path))

    # -- quarantine ---------------------------------------------------------

    def quarantine_add(self, sha256: str, scope: str, path: str, reason: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO quarantine (sha256, scope, path, reason, at) VALUES (?,?,?,?,?)",
            (sha256, scope, path, reason, int(time.time())),
        )

    def quarantined(self) -> set[str]:
        """Content hashes that must not be applied again.

        Keyed on content, not path: a path-keyed quarantine just re-downloads
        the same broken jar on the very next poll.
        """
        return {row["sha256"] for row in self._db.execute("SELECT sha256 FROM quarantine")}

    def quarantine_clear(self) -> int:
        cursor = self._db.execute("DELETE FROM quarantine")
        return cursor.rowcount

    # -- breaker ------------------------------------------------------------

    def breaker_reason(self, name: str) -> str | None:
        row = self._db.execute("SELECT reason FROM breaker WHERE name = ?", (name,)).fetchone()
        return row["reason"] if row else None

    def trip_breaker(self, name: str, reason: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO breaker (name, reason, at) VALUES (?,?,?)",
            (name, reason, int(time.time())),
        )

    def reset_breaker(self, name: str) -> None:
        self._db.execute("DELETE FROM breaker WHERE name = ?", (name,))

    # -- flags --------------------------------------------------------------
    #
    # For work that outlives the process. A restart deferred because the server
    # was unreachable must still happen after bifrost itself is restarted,
    # otherwise the files sit on disk and the server never picks them up.

    def set_flag(self, name: str, value: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO flags (name, value, at) VALUES (?,?,?)",
            (name, value, int(time.time())),
        )

    def get_flag(self, name: str) -> str | None:
        row = self._db.execute("SELECT value FROM flags WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else None

    def clear_flag(self, name: str) -> None:
        self._db.execute("DELETE FROM flags WHERE name = ?", (name,))
