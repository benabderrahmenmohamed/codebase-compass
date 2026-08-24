"""Persistent storage for analyses and projects, on SQLite.

This file replaces the in-memory lists it used to hold. Nothing else in the
project changed: the functions below keep the same names, take the same
arguments and return the same dictionaries. That was the point of putting a
seam here, and this is it being spent.

Three limits of the old version are gone: data survives a restart, several
workers see the same data, and a lookup by id is an indexed query rather
than a walk down a list.

**Why JSON in a column rather than eight tables.**
An analysis is deeply nested — five category scores, a list of findings, a
list of file reports, an optional block of model explanations. Normalising
that would be a large change whose only immediate benefit is queries nobody
makes yet, and it would break the promise above, because every caller
expects these dicts back exactly as they were stored. So each record is one
JSON document with its id and timestamp lifted out into indexed columns.
Splitting it up is a decision for the day something needs to ask a question
*inside* a report — filtering every analysis by security score, say.

**Why a connection per call.**
FastAPI runs synchronous endpoints in a thread pool, and a sqlite3
connection may not be shared across threads. Opening one per call is the
simple correct answer; SQLite is a file, and this costs microseconds at the
volumes involved. A pool is an optimisation to make when measurement asks
for it.

Important rule, unchanged: this module knows nothing about HTTP. No 404
here — we return None and the router decides what to do with it.
"""

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "data" / "compass.db"

# Tables are created once per path, not on every connection.
_initialised: set[str] = set()


def db_path() -> Path:
    """Where the database lives.

    Read from the environment every time rather than captured at import, so
    a test can point it somewhere temporary without the import order
    mattering — the same mistake that let a deleted API key come back from
    the .env file during test setup.
    """
    configured = os.environ.get("COMPASS_DB")
    return Path(configured) if configured else DEFAULT_DB_PATH


SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
    project_id  TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    data        TEXT NOT NULL
);
"""


def _connect() -> sqlite3.Connection:
    path = db_path()
    key = str(path)

    if key not in _initialised:
        if path.parent != Path("."):
            path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(key)
        try:
            connection.executescript(SCHEMA)
            connection.commit()
        finally:
            connection.close()
        _initialised.add(key)

    connection = sqlite3.connect(key)
    connection.row_factory = sqlite3.Row
    return connection


# --------------------------------------------------------------------------
# Encoding
#
# A record holds datetimes, which JSON cannot represent. They are written as
# ISO 8601 strings and read back as datetimes, so a caller never has to know
# the value made a round trip through text.
# --------------------------------------------------------------------------

DATETIME_KEYS = ("created_at",)


def _encode(record: dict) -> str:
    def default(value):
        if isinstance(value, datetime):
            return value.isoformat()
        raise TypeError(f"{type(value).__name__} is not JSON serialisable")

    return json.dumps(record, default=default)


def _decode(text: str) -> dict:
    record = json.loads(text)
    for key in DATETIME_KEYS:
        value = record.get(key)
        if isinstance(value, str):
            try:
                record[key] = datetime.fromisoformat(value)
            except ValueError:
                # Leave it as text rather than lose it: an unreadable
                # timestamp is a smaller problem than a record that will
                # not load at all.
                pass
    return record


def _timestamp(record: dict) -> str:
    value = record.get("created_at")
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value or "")


# --------------------------------------------------------------------------
# Analyses
# --------------------------------------------------------------------------


def save(analysis: dict) -> dict:
    """Store an analysis and return it."""
    with _connect() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO analyses (id, created_at, data) VALUES (?, ?, ?)",
            (analysis["id"], _timestamp(analysis), _encode(analysis)),
        )
    return analysis


def get_all() -> list[dict]:
    """Return every analysis, oldest first."""
    # Ordered by rowid, which is insertion order. Ordering by created_at
    # would tie for two analyses stored in the same microsecond, and the
    # history would shuffle between reads.
    with _connect() as connection:
        rows = connection.execute("SELECT data FROM analyses ORDER BY rowid").fetchall()
    return [_decode(row["data"]) for row in rows]


def get_by_id(analysis_id: str) -> dict | None:
    """Look up an analysis by id. Returns None if it does not exist."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT data FROM analyses WHERE id = ?", (analysis_id,)
        ).fetchone()
    return _decode(row["data"]) if row else None


# --------------------------------------------------------------------------
# Projects — same pattern
# --------------------------------------------------------------------------


def save_project(project: dict) -> dict:
    """Store a project and return it."""
    with _connect() as connection:
        connection.execute(
            "INSERT OR REPLACE INTO projects (project_id, created_at, data) "
            "VALUES (?, ?, ?)",
            (project["project_id"], _timestamp(project), _encode(project)),
        )
    return project


def get_all_projects() -> list[dict]:
    """Return every project, oldest first."""
    with _connect() as connection:
        rows = connection.execute("SELECT data FROM projects ORDER BY rowid").fetchall()
    return [_decode(row["data"]) for row in rows]


def get_project_by_id(project_id: str) -> dict | None:
    """Look up a project by id. Returns None if it does not exist."""
    with _connect() as connection:
        row = connection.execute(
            "SELECT data FROM projects WHERE project_id = ?", (project_id,)
        ).fetchone()
    return _decode(row["data"]) if row else None


# --------------------------------------------------------------------------
# Maintenance
# --------------------------------------------------------------------------


def clear() -> None:
    """Empty the store completely (analyses AND projects).

    Used by tests, so each one starts from a clean slate and does not depend
    on what another test left behind.
    """
    with _connect() as connection:
        connection.execute("DELETE FROM analyses")
        connection.execute("DELETE FROM projects")
