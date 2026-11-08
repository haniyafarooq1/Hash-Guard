"""SQLite storage layer for Hash Guard.

Provides the single SQLite database used for scan history, activity
events, security alerts and report snapshots.

Design notes
------------
* The database file lives OUTSIDE the monitored directories (by default
  in ``~/.hash_guard/``) so that Hash Guard never detects its own
  database changes.  The location can be overridden with
  :func:`set_database_path` (used by the test suite) or with the
  ``HASHGUARD_DB`` environment variable.
* Every connection enables SQLite foreign-key enforcement, as required
  by the TRD (section 7.3).
* All statements use parameterized SQL.
* Connections are cached per thread (FastAPI runs sync endpoints in a
  worker-thread pool), so every thread keeps its own isolated
  connection.
"""

import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

DEFAULT_DB_DIR = Path.home() / ".hash_guard"
DEFAULT_DB_NAME = "hashguard.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    directory           TEXT NOT NULL,
    scan_time           TEXT NOT NULL,
    integrity_status    TEXT NOT NULL,
    suspicious_status   TEXT,
    baseline_status     TEXT NOT NULL,
    overall_status      TEXT NOT NULL,
    integrity_summary   TEXT NOT NULL,
    suspicious_summary  TEXT,
    integrity_result    TEXT NOT NULL,
    suspicious_result   TEXT,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_logs (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    event_type  TEXT NOT NULL,
    source      TEXT NOT NULL,
    file_path   TEXT,
    description TEXT NOT NULL,
    severity    TEXT NOT NULL,
    details     TEXT,
    timestamp   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_activity_logs_scan_id  ON activity_logs(scan_id);
CREATE INDEX IF NOT EXISTS idx_activity_logs_type     ON activity_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_activity_logs_severity ON activity_logs(severity);
CREATE INDEX IF NOT EXISTS idx_activity_logs_time     ON activity_logs(timestamp);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    dedupe_key  TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    category    TEXT NOT NULL,
    severity    TEXT NOT NULL,
    file_path   TEXT,
    status      TEXT NOT NULL DEFAULT 'unread',
    timestamp   TEXT NOT NULL,
    UNIQUE (scan_id, dedupe_key)
);
CREATE INDEX IF NOT EXISTS idx_alerts_scan_id  ON alerts(scan_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(category);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_time     ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS reports (
    report_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      INTEGER NOT NULL UNIQUE REFERENCES scans(scan_id) ON DELETE CASCADE,
    report_data  TEXT NOT NULL,
    generated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id);
"""

_lock = threading.RLock()       # guards the path settings
_local = threading.local()       # per-thread connection cache
_db_path_override = None
_initialized_paths = set()


def now_iso():
    """Return the current local time as a timezone-aware ISO 8601 string."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _resolve_path():
    """Return ``(Path, is_default)`` for the currently configured database."""
    if _db_path_override is not None:
        return Path(_db_path_override), False
    env_path = os.environ.get("HASHGUARD_DB")
    if env_path:
        return Path(env_path), False
    return DEFAULT_DB_DIR / DEFAULT_DB_NAME, True


def _close_quietly(conn):
    """Close a connection, ignoring an already-closed one."""
    try:
        conn.close()
    except sqlite3.ProgrammingError:
        # Already closed earlier - nothing left to do.
        pass


def get_database_path():
    """Return the path of the SQLite database file currently in use."""
    with _lock:
        return _resolve_path()[0]


def set_database_path(path):
    """Point Hash Guard storage at a specific SQLite file.

    Passing ``None`` restores the default location.  Used by the test
    suite to run every test against an isolated temporary database.
    """
    global _db_path_override
    with _lock:
        _db_path_override = str(path) if path is not None else None
        if _db_path_override is not None:
            _initialized_paths.discard(_db_path_override)


def reset_connections():
    """Close this thread's cached connection and clear the cache.

    Intended for test teardown and process shutdown: each thread closes
    its own connection so the database file becomes writable and
    deletable again.
    """
    conn = getattr(_local, "conn", None)
    if conn is not None:
        _close_quietly(conn)
    _local.conn = None
    _local.path = None


def get_connection():
    """Return this thread's SQLite connection with FK enforcement on.

    Connections are cached per thread and reused while the configured
    database path stays the same; when the path changes the cached
    connection is closed and a fresh one is opened.
    """
    with _lock:
        path, is_default = _resolve_path()
    path_str = str(path)

    conn = getattr(_local, "conn", None)
    if conn is not None and getattr(_local, "path", None) == path_str:
        return conn
    if conn is not None:
        _close_quietly(conn)

    # Make sure the default database directory exists.
    if is_default:
        path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(path_str, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    _local.conn = conn
    _local.path = path_str
    return conn


def init_db():
    """Create the tables and indexes if they do not exist yet (idempotent)."""
    path_str = str(_resolve_path()[0])
    with _lock:
        if path_str in _initialized_paths:
            return
        conn = get_connection()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        _initialized_paths.add(path_str)
