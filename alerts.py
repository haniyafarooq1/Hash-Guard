"""Hash Guard – Security Alerts (alerts.py).

Generates user-visible security alerts from the results produced by the
integrity checker and the suspicious file detector (FR-08..FR-16), and
manages alert retrieval, filtering and status transitions.

Key behaviours required by the TRD:
* Alert severities are configurable at runtime (FR-08) via
  :func:`set_severity_config` instead of being hard-coded in the frontend.
* ``baseline_unavailable`` always produces a CRITICAL alert and is never
  reported as a clean scan (FR-09).
* Errors produce system alerts, and never discard valid findings (FR-10).
* The ``suspicious_files`` array is the single primary source for
  suspicious-file alerts; a file that also appears in
  ``executable_files`` / ``newly_added_files`` does NOT produce
  additional alerts (FR-14).
* Generating alerts twice for the same scan never creates duplicates:
  every alert carries a stable ``dedupe_key`` and the database enforces
  ``UNIQUE (scan_id, dedupe_key)`` (FR-14).
* A completely clean scan produces no alerts at all (FR-16).
* Dismissed alerts stay in the database for historical reporting (FR-13).

This module only reads the result dictionaries; it never recalculates
hashes, verifies the baseline or repeats detection logic.
"""

import json
import sqlite3
from datetime import datetime

from backend.storage import database

# ---------------------------------------------------------------------------
# Public vocabulary
# ---------------------------------------------------------------------------

SEVERITIES = ("critical", "high", "medium", "low", "info")

CATEGORIES = ("integrity", "suspicious_file", "baseline", "system")

ALERT_STATUSES = ("unread", "read", "dismissed")

# Default severities per TRD FR-08.  Values can be overridden at runtime
# with set_severity_config() so they are configurable rather than
# permanently embedded anywhere (frontend included).
DEFAULT_SEVERITY_CONFIG = {
    "file_modified": "high",
    "file_added": "medium",
    "file_deleted": "high",
    "file_renamed": "medium",
    "suspicious_executable": "high",
    "suspicious_other": "medium",
    "baseline_unavailable": "critical",
    "invalid_directory": "medium",
    "scan_error": "medium",
}

_severity_config = dict(DEFAULT_SEVERITY_CONFIG)


def set_severity_config(overrides):
    """Override one or more default alert severities (FR-08).

    Example::

        set_severity_config({"file_added": "low", "file_modified": "critical"})
    """
    if not isinstance(overrides, dict):
        raise ValueError("severity overrides must be a dictionary")
    for key, value in overrides.items():
        if key not in DEFAULT_SEVERITY_CONFIG:
            raise ValueError(
                "Unknown severity rule '{}'. Supported rules: {}".format(
                    key, ", ".join(sorted(DEFAULT_SEVERITY_CONFIG))
                )
            )
        if value not in SEVERITIES:
            raise ValueError(
                "Unsupported severity '{}'. Supported values: {}".format(
                    value, ", ".join(SEVERITIES)
                )
            )
    _severity_config.update(overrides)


def get_severity_config():
    """Return a copy of the currently active severity configuration."""
    return dict(_severity_config)


def reset_severity_config():
    """Restore the default severity configuration."""
    _severity_config.clear()
    _severity_config.update(DEFAULT_SEVERITY_CONFIG)


# ---------------------------------------------------------------------------
# Local read-only helpers (module stays standalone)
# ---------------------------------------------------------------------------

def _items(result, key):
    if not isinstance(result, dict):
        return []
    value = result.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _status(result):
    if not isinstance(result, dict):
        return None
    status = result.get("status")
    return status if isinstance(status, str) else None


def _json_loads(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def _validate_pagination(limit, offset):
    try:
        limit = int(limit)
        offset = int(offset)
    except (TypeError, ValueError):
        raise ValueError("limit and offset must be integers")
    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    if offset < 0:
        raise ValueError("offset must be 0 or greater")
    return limit, offset


def _normalize_date(value, end_of_day):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 10:
        text += "T23:59:59" if end_of_day else "T00:00:00"
    try:
        datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            "Invalid date filter '{}'. Use YYYY-MM-DD or an ISO 8601 timestamp.".format(value)
        )
    return text


def _row_to_alert(row):
    return {
        "alert_id": row["alert_id"],
        "scan_id": row["scan_id"],
        "dedupe_key": row["dedupe_key"],
        "title": row["title"],
        "description": row["description"],
        "category": row["category"],
        "severity": row["severity"],
        "file_path": row["file_path"],
        "status": row["status"],
        "timestamp": row["timestamp"],
    }


# ---------------------------------------------------------------------------
# FR-08 .. FR-10, FR-14, FR-16: alert generation
# ---------------------------------------------------------------------------

def generate_alerts(integrity_result, suspicious_result, scan_id):
    """Generate and persist alerts for one scan.

    ``scan_id`` must reference a scan already recorded by
    ``activity_logger.log_scan()`` (alerts carry a foreign key to it).
    Re-running this function for the same scan is safe: existing alerts
    are kept and no duplicates are created (FR-14).

    Returns the list of all alerts stored for this scan.
    """
    if not isinstance(integrity_result, dict):
        raise ValueError(
            "integrity_result must be the dictionary returned by check_integrity()"
        )
    if suspicious_result is not None and not isinstance(suspicious_result, dict):
        raise ValueError(
            "suspicious_result must be the dictionary returned by "
            "check_suspicious_files() or None"
        )
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")

    database.init_db()
    conn = database.get_connection()

    scan_row = conn.execute(
        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if scan_row is None:
        raise ValueError(
            "No recorded scan with id {}. Call log_scan() before "
            "generating alerts.".format(scan_id)
        )

    integrity_status = _status(integrity_result)
    suspicious_status = _status(suspicious_result)
    config = get_severity_config()

    # Canonical alert timestamp: the integrity result's scan time.
    timestamp = (
        integrity_result.get("scan_time")
        if isinstance(integrity_result.get("scan_time"), str)
        else database.now_iso()
    )

    candidates = []

    # FR-09: baseline security alert, critical by default.
    if integrity_status == "baseline_unavailable":
        candidates.append({
            "dedupe_key": "baseline_unavailable",
            "title": "Baseline Unavailable or Authentication Failed",
            "description": (
                "Hash Guard could not load or authenticate the baseline. "
                "File-integrity comparison was not performed. Review the "
                "baseline file, signature and secret-key availability."
            ),
            "category": "baseline",
            "severity": config["baseline_unavailable"],
            "file_path": None,
        })

    # Invalid monitoring directory (single alert even if both modules report it)
    if integrity_status == "invalid_directory" or suspicious_status == "invalid_directory":
        candidates.append({
            "dedupe_key": "invalid_directory",
            "title": "Invalid Monitoring Directory",
            "description": (
                "The monitoring directory is invalid or unavailable. "
                "The scan could not be completed."
            ),
            "category": "system",
            "severity": config["invalid_directory"],
            "file_path": None,
        })

    # FR-08: integrity findings
    for item in _items(integrity_result, "modified"):
        path = item.get("path")
        candidates.append({
            "dedupe_key": "modified:{}".format(path),
            "title": "File Modified",
            "description": "Monitored file '{}' has been modified.".format(path),
            "category": "integrity",
            "severity": config["file_modified"],
            "file_path": path,
        })

    for item in _items(integrity_result, "added"):
        path = item.get("path")
        candidates.append({
            "dedupe_key": "added:{}".format(path),
            "title": "File Added",
            "description": "New file '{}' was detected in the monitored directory.".format(path),
            "category": "integrity",
            "severity": config["file_added"],
            "file_path": path,
        })

    for item in _items(integrity_result, "deleted"):
        path = item.get("path")
        candidates.append({
            "dedupe_key": "deleted:{}".format(path),
            "title": "File Deleted",
            "description": "Monitored file '{}' is missing from the monitored directory.".format(path),
            "category": "integrity",
            "severity": config["file_deleted"],
            "file_path": path,
        })

    for item in _items(integrity_result, "renamed"):
        old_path = item.get("old_path")
        new_path = item.get("new_path")
        candidates.append({
            "dedupe_key": "renamed:{}->{}".format(old_path, new_path),
            "title": "File Renamed",
            "description": (
                "File '{}' appears to have been renamed to '{}' "
                "(identical SHA-256 hash).".format(old_path, new_path)
            ),
            "category": "integrity",
            "severity": config["file_renamed"],
            "file_path": new_path,
        })

    # FR-08 / FR-14: suspicious files – the suspicious_files array is the
    # ONLY source of suspicious-file alerts.  executable_files and
    # newly_added_files overlap with it and are merely cross-referenced to
    # pick the severity (executable finding -> high).
    if suspicious_result is not None and suspicious_status != "invalid_directory":
        executable_paths = {
            item.get("path") for item in _items(suspicious_result, "executable_files")
        }
        for item in _items(suspicious_result, "suspicious_files"):
            path = item.get("path")
            reasons = item.get("reasons") if isinstance(item.get("reasons"), list) else []
            # Executable finding -> 'suspicious_executable' rule.  The
            # executable_files array is the primary signal; the detector's
            # own severity ('high' exactly when executable) is used as a
            # fallback when that array is not present in the result.
            is_executable = path in executable_paths or item.get("severity") == "high"
            candidates.append({
                "dedupe_key": "suspicious:{}".format(path),
                "title": "Suspicious File Detected",
                "description": "File '{}' was flagged: {}".format(
                    path,
                    "; ".join(reasons) if reasons else "no reasons reported by the detector",
                ),
                "category": "suspicious_file",
                "severity": (
                    config["suspicious_executable"] if is_executable
                    else config["suspicious_other"]
                ),
                "file_path": path,
            })

    # FR-10: errors produce system alerts.  For baseline_unavailable and
    # invalid_directory the dedicated alerts above already describe the
    # failure (the modules' error arrays contain exactly that failure),
    # so those entries are not alerted twice.
    if integrity_status not in ("baseline_unavailable", "invalid_directory"):
        for item in _items(integrity_result, "errors"):
            candidates.append({
                "dedupe_key": "error:integrity_checker:{}:{}".format(
                    item.get("path"), item.get("message")
                ),
                "title": "Integrity Check Error",
                "description": "The integrity checker reported an error{}: {}".format(
                    " for '{}'".format(item.get("path")) if item.get("path") else "",
                    item.get("message"),
                ),
                "category": "system",
                "severity": config["scan_error"],
                "file_path": item.get("path"),
            })

    if suspicious_result is not None and suspicious_status != "invalid_directory":
        for item in _items(suspicious_result, "errors"):
            candidates.append({
                "dedupe_key": "error:suspicious_detector:{}:{}".format(
                    item.get("path"), item.get("message")
                ),
                "title": "Suspicious Detection Error",
                "description": "The suspicious-file detector reported an error{}: {}".format(
                    " for '{}'".format(item.get("path")) if item.get("path") else "",
                    item.get("message"),
                ),
                "category": "system",
                "severity": config["scan_error"],
                "file_path": item.get("path"),
            })

    # FR-14: INSERT OR IGNORE + UNIQUE(scan_id, dedupe_key) makes this
    # idempotent for repeated generation against the same scan.
    with conn:
        conn.executemany(
            """
            INSERT OR IGNORE INTO alerts (
                scan_id, dedupe_key, title, description, category,
                severity, file_path, status, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'unread', ?)
            """,
            [
                (
                    scan_id, alert["dedupe_key"], alert["title"],
                    alert["description"], alert["category"], alert["severity"],
                    alert["file_path"], timestamp,
                )
                for alert in candidates
            ],
        )

    rows = conn.execute(
        "SELECT * FROM alerts WHERE scan_id = ? ORDER BY alert_id ASC",
        (scan_id,),
    ).fetchall()
    return [_row_to_alert(row) for row in rows]


# ---------------------------------------------------------------------------
# FR-13 / FR-15: retrieval, filtering and status management
# ---------------------------------------------------------------------------

def get_alerts(severity=None, category=None, status=None, scan_id=None,
               start_date=None, end_date=None, limit=50, offset=0):
    """Return filtered and paginated alerts (FR-15)."""
    limit, offset = _validate_pagination(limit, offset)
    database.init_db()
    conn = database.get_connection()

    clauses = []
    params = []
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))
    if category:
        clauses.append("category = ?")
        params.append(str(category))
    if status:
        clauses.append("status = ?")
        params.append(str(status))
    if scan_id is not None:
        try:
            clauses.append("scan_id = ?")
            params.append(int(scan_id))
        except (TypeError, ValueError):
            raise ValueError("scan_id must be an integer")
    start = _normalize_date(start_date, end_of_day=False)
    if start:
        clauses.append("datetime(timestamp) >= datetime(?)")
        params.append(start)
    end = _normalize_date(end_date, end_of_day=True)
    if end:
        clauses.append("datetime(timestamp) <= datetime(?)")
        params.append(end)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    total = conn.execute("SELECT COUNT(*) FROM alerts" + where, params).fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM alerts" + where
        + " ORDER BY datetime(timestamp) DESC, alert_id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    return {
        "items": [_row_to_alert(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def get_alert_by_id(alert_id):
    """Retrieve an individual alert, or None when it does not exist."""
    try:
        alert_id = int(alert_id)
    except (TypeError, ValueError):
        raise ValueError("alert_id must be an integer")
    database.init_db()
    conn = database.get_connection()

    row = conn.execute(
        "SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)
    ).fetchone()
    return _row_to_alert(row) if row is not None else None


def update_alert_status(alert_id, status):
    """Update an alert to 'unread', 'read' or 'dismissed' (FR-13).

    Unsupported status values are rejected with ValueError.  Returns the
    updated alert, or None when the alert id does not exist.
    """
    if status not in ALERT_STATUSES:
        raise ValueError(
            "Unsupported alert status '{}'. Supported values: {}".format(
                status, ", ".join(ALERT_STATUSES)
            )
        )
    try:
        alert_id = int(alert_id)
    except (TypeError, ValueError):
        raise ValueError("alert_id must be an integer")

    database.init_db()
    conn = database.get_connection()

    with conn:
        cursor = conn.execute(
            "UPDATE alerts SET status = ? WHERE alert_id = ?", (status, alert_id)
        )
    if cursor.rowcount == 0:
        return None
    return get_alert_by_id(alert_id)


def get_alert_summary():
    """Return aggregate counts used by dashboards (total / unread / per level)."""
    database.init_db()
    conn = database.get_connection()

    by_severity = {severity: 0 for severity in SEVERITIES}
    for row in conn.execute("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity"):
        by_severity[row["severity"]] = row["n"]

    by_status = {status: 0 for status in ALERT_STATUSES}
    for row in conn.execute("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status"):
        by_status[row["status"]] = row["n"]

    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    return {
        "total": total,
        "unread": by_status.get("unread", 0),
        "by_severity": by_severity,
        "by_status": by_status,
    }
