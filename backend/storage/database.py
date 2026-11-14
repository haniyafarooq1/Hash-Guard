"""SQLite storage layer for Hash Guard.

Provides the single SQLite database used for scan history, activity
events, security alerts and report snapshots.

Design notes
------------
* The database file lives OUTSIDE the monitored directories (by default
  in ``~/.hash_guard/``) so that Hash Guard never detects its own
  database changes.  The location can be overridden with
  :func:`set_database_path` (used by the test suite) or with the
  ``HASHGUARD_DB`` environment variable.  Parent directories of custom
  locations are created automatically.
* Every connection enables SQLite foreign-key enforcement, as required
  by the TRD (section 7.3).
* All statements use parameterized SQL.
* Connection lifecycle (thread safety):

  - Connections are created with ``check_same_thread=False`` and cached
    PER THREAD (FastAPI runs sync endpoints in a worker-thread pool),
    so during normal operation every thread keeps its own isolated
    connection that is never shared with other threads.
  - In addition, every connection ever created is tracked in a
    process-wide registry guarded by a lock.  This is what makes
    :func:`reset_connections` able to close the connections that belong
    to OTHER threads: test teardown runs on the main thread while
    worker threads still hold cached connections, and on Windows an
    open SQLite handle keeps the database file locked (WinError 32,
    "The process cannot access the file").  Closing a connection from
    another thread is exactly what ``check_same_thread=False`` plus the
    registry lock makes safe.
  - A thread whose cached connection was closed by a reset detects the
    stale entry through the registry and transparently reopens on its
    next use.
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

_lock = threading.RLock()       # guards _registry and the path settings
_local = threading.local()       # per-thread connection cache (normal operation)
_registry = {}                   # id(conn) -> conn, ALL live connections across threads
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
    """Close a connection and drop it from the registry (best effort)."""
    try:
        conn.close()
    except sqlite3.ProgrammingError:
        # Already closed earlier - nothing left to do.
        pass
    with _lock:
        if _registry.get(id(conn)) is conn:
            del _registry[id(conn)]


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
    """Close ALL tracked connections and clear the connection caches.

    Unlike the per-thread cache, the registry tracks every connection
    created by ANY thread, so this closes the connections that FastAPI
    worker threads still hold cached - the situation that otherwise
    keeps the database file undeletable on Windows (WinError 32).

    Intended for test teardown and process shutdown, when no request is
    being served concurrently.  Connections that their owning thread
    already closed are skipped; every other connection is closed so the
    database file becomes writable/deletable again.  Threads that later
    reuse a now-stale cached connection transparently reopen one via
    the registry check in :func:`get_connection`.
    """
    with _lock:
        connections = list(_registry.values())
        _registry.clear()
        _initialized_paths.clear()
    for conn in connections:
        try:
            conn.close()
        except sqlite3.ProgrammingError:
            # Already closed by its owning thread - nothing left to do.
            pass
    # Clear the CALLING thread's cache directly; other threads detect
    # their stale entries through the (now empty) registry.
    _local.conn = None
    _local.path = None


def get_connection():
    """Return this thread's SQLite connection with FK enforcement on.

    Connections remain isolated per thread during normal operation.  A
    cached entry is discarded when the configured database path changed
    or when the entry is no longer registered (i.e. it was closed by a
    ``reset_connections()`` call from another thread), in which case a
    fresh connection is opened transparently.
    """
    with _lock:
        path, _is_default = _resolve_path()
    path_str = str(path)

    conn = getattr(_local, "conn", None)
    if (
        conn is not None
        and getattr(_local, "path", None) == path_str
        and _registry.get(id(conn)) is conn
    ):
        return conn

    if conn is not None:
        _close_quietly(conn)

    # Parent directories are created for custom locations too, so a
    # configured path such as .../data/hashguard.db works out of the box.
    path.parent.mkdir(parents=True, exist_ok=True)

    # check_same_thread=False is required so reset_connections() can
    # close this connection from another thread (test teardown); the
    # connection itself is still only ever USED by its owning thread.
    conn = sqlite3.connect(path_str, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 30000")

    with _lock:
        _registry[id(conn)] = conn
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
