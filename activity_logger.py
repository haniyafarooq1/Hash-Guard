"""Hash Guard – Activity Logger (activity_logger.py).

Records every scan attempt and its outcome (FR-01), the file-integrity
findings (FR-02), suspicious-file findings (FR-03) and errors/security
failures (FR-04) returned by the integrity checker and the suspicious
file detector, and exposes the recorded history with filtering and
pagination (FR-05, FR-06).

Integration rules (TRD section 2.3) respected by this module:
* it NEVER recalculates hashes, loads or verifies the baseline, or
  repeats suspicious-file detection;
* it never modifies the result dictionaries produced by
  ``check_integrity()`` / ``check_suspicious_files()`` (read-only access);
* it does not assume optional fields exist (all access uses ``.get()``);
* original statuses are preserved as-is, including the current
  ``baseline_unavailable`` behaviour for empty baselines (see the
  coordination note in the project README).

Timestamps are stored as timezone-aware ISO 8601 strings and the
timezone offset supplied by the original scan result is preserved
(FR-07).  The integrity result's ``scan_time`` is the canonical scan
timestamp for the scan row and all of its activity events.
"""

import json
import sqlite3
from datetime import datetime

from backend.storage import database

# ---------------------------------------------------------------------------
# Public vocabulary
# ---------------------------------------------------------------------------

EVENT_TYPES = (
    "scan_recorded",
    "file_modified",
    "file_added",
    "file_deleted",
    "file_renamed",
    "suspicious_file",
    "baseline_unavailable",
    "invalid_directory",
    "scan_incomplete",
    "scan_error",
)

SEVERITIES = ("critical", "high", "medium", "low", "info")

SOURCES = ("integrity_checker", "suspicious_detector", "system")

BASELINE_STATUSES = ("verified", "unavailable_or_unverified", "not_checked")

OVERALL_STATUSES = (
    "clean",
    "findings_detected",
    "completed_with_errors",
    "incomplete",
    "baseline_unavailable",
    "invalid_directory",
)

# Statuses that mean a detection stage actually ran and finished.  A
# scan can only be assessed further (and eventually be marked clean)
# when BOTH stages report one of these.  Anything else - a missing
# result, ``not_started``, a stage crash (``failed``) or an unknown
# status - makes the scan incomplete and it must never appear clean.
COMPLETED_STAGE_STATUSES = ("success", "completed_with_errors")


# ---------------------------------------------------------------------------
# Local read-only helpers (kept private so each module stays
# standalone and does not depend on the internals of the others)
# ---------------------------------------------------------------------------

def _items(result, key):
    """Safely return result[key] as a list of dicts (never assumes fields)."""
    if not isinstance(result, dict):
        return []
    value = result.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _summary(result):
    if not isinstance(result, dict):
        return {}
    summary = result.get("summary")
    return dict(summary) if isinstance(summary, dict) else {}


def _count(result, key):
    value = _summary(result).get(key)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _status(result):
    if not isinstance(result, dict):
        return None
    status = result.get("status")
    return status if isinstance(status, str) else None


def _scan_time(result):
    if isinstance(result, dict):
        value = result.get("scan_time")
        if isinstance(value, str) and value:
            return value
    return database.now_iso()


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
    """Normalize a date/datetime filter to a comparable ISO 8601 value."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) == 10:  # date only: YYYY-MM-DD
        text += "T23:59:59" if end_of_day else "T00:00:00"
    try:
        datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(
            "Invalid date filter '{}'. Use YYYY-MM-DD or an ISO 8601 timestamp.".format(value)
        )
    return text


# ---------------------------------------------------------------------------
# Derived assessments (FR-19 priority rules, conservative by design)
# ---------------------------------------------------------------------------

def derive_baseline_status(integrity_result):
    """Derive the baseline assessment from the integrity result only.

    ``invalid_directory``  -> ``not_checked``
    ``baseline_unavailable`` -> ``unavailable_or_unverified``
    ``success`` / ``completed_with_errors`` -> ``verified``
    anything else -> ``not_checked`` (never invent information)
    """
    status = _status(integrity_result)
    if status == "baseline_unavailable":
        return "unavailable_or_unverified"
    if status == "invalid_directory":
        return "not_checked"
    if status in ("success", "completed_with_errors"):
        return "verified"
    return "not_checked"


def derive_overall_status(integrity_result, suspicious_result=None):
    """Derive the overall assessment using the TRD FR-19 priority rules.

    1. ``invalid_directory``      – integrity checker reports an invalid directory
    2. ``baseline_unavailable``   – integrity checker reports an unavailable baseline
    3. ``incomplete``             – a required detection stage is missing,
                                     failed or reported an unknown status
    4. ``completed_with_errors``  – either module reports errors
    5. ``findings_detected``      – any change or suspicious finding exists
    6. ``clean``                  – only when BOTH checks ran and succeeded
                                     with no findings and no errors

    A scan is marked ``clean`` only when the integrity check AND the
    suspicious-file detection both ran and completed successfully with
    no findings and no errors.  A missing suspicious result, a stage
    that never started, crashed or reported an unknown status yields
    ``incomplete`` - never a clean result.
    """
    integrity_status = _status(integrity_result)
    suspicious_status = _status(suspicious_result)

    # 1. invalid directory (integrity result is authoritative for the scan)
    if integrity_status == "invalid_directory":
        return "invalid_directory"

    # 2. baseline unavailable / authentication failure
    if integrity_status == "baseline_unavailable":
        return "baseline_unavailable"

    # 3. a required stage is missing, failed or unknown -> the scan did
    #    not complete.  Like the other failure conditions this outranks
    #    findings, and it can never be reported as clean.
    integrity_completed = integrity_status in COMPLETED_STAGE_STATUSES
    suspicious_completed = (
        suspicious_result is not None
        and suspicious_status in COMPLETED_STAGE_STATUSES
    )
    if not integrity_completed or not suspicious_completed:
        return "incomplete"

    # 4. errors reported by either module
    has_errors = (
        _count(integrity_result, "errors") > 0
        or integrity_status == "completed_with_errors"
        or (
            suspicious_result is not None
            and (
                _count(suspicious_result, "errors") > 0
                or suspicious_status == "completed_with_errors"
                or suspicious_status == "invalid_directory"
            )
        )
    )
    if has_errors:
        return "completed_with_errors"

    # 5. findings detected
    has_findings = (
        _count(integrity_result, "modified") > 0
        or _count(integrity_result, "added") > 0
        or _count(integrity_result, "deleted") > 0
        or _count(integrity_result, "renamed") > 0
        or (
            suspicious_result is not None
            and (
                _count(suspicious_result, "suspicious_files") > 0
                or _count(suspicious_result, "newly_added_files") > 0
                or _count(suspicious_result, "executable_files") > 0
            )
        )
    )
    if has_findings:
        return "findings_detected"

    # 6. clean – only reachable when both stages completed successfully
    #    (checked in step 3) with no errors and no findings.
    return "clean"


# ---------------------------------------------------------------------------
# FR-01 .. FR-04: recording
# ---------------------------------------------------------------------------

def _build_events(integrity_result, suspicious_result, integrity_status,
                  suspicious_status, baseline_status, overall_status):
    """Build the activity events for one scan (pure, no I/O)."""
    events = []

    events.append((
        "scan_recorded",
        "system",
        None,
        "Scan recorded (integrity: {}, suspicious: {}, overall: {}).".format(
            integrity_status,
            suspicious_status if suspicious_status is not None else "not_run",
            overall_status,
        ),
        "info",
        {
            "integrity_status": integrity_status,
            "suspicious_status": suspicious_status,
            "baseline_status": baseline_status,
            "overall_status": overall_status,
        },
    ))

    if integrity_status == "baseline_unavailable":
        events.append((
            "baseline_unavailable",
            "integrity_checker",
            None,
            "Baseline unavailable or authentication failed. "
            "File-integrity comparison was not performed.",
            "critical",
            {"integrity_status": integrity_status},
        ))

    if integrity_status == "invalid_directory":
        events.append((
            "invalid_directory",
            "integrity_checker",
            None,
            "Invalid or unavailable monitoring directory.",
            "medium",
            {"integrity_status": integrity_status},
        ))

    # A required detection stage is missing, failed or unknown: the scan
    # did not complete and must not be treated as a clean result.
    if overall_status == "incomplete":
        reasons = []
        if integrity_status not in COMPLETED_STAGE_STATUSES:
            reasons.append(
                "the integrity-checking stage did not complete (status: {})".format(
                    integrity_status or "unknown"
                )
            )
        if suspicious_result is None:
            reasons.append("the suspicious-file detection stage did not run")
        elif suspicious_status not in COMPLETED_STAGE_STATUSES:
            reasons.append(
                "the suspicious-file detection stage did not complete "
                "(status: {})".format(suspicious_status or "unknown")
            )
        events.append((
            "scan_incomplete",
            "system",
            None,
            "Scan incomplete: {}. The result must not be treated as "
            "clean.".format(" and ".join(reasons) or "an unknown failure occurred"),
            "high",
            {
                "integrity_status": integrity_status,
                "suspicious_status": suspicious_status,
            },
        ))

    # FR-02: integrity findings
    for item in _items(integrity_result, "modified"):
        path = item.get("path")
        events.append((
            "file_modified", "integrity_checker", path,
            "File modified: {}".format(path), "high",
            {"baseline_hash": item.get("baseline_hash"),
             "current_hash": item.get("current_hash")},
        ))

    for item in _items(integrity_result, "added"):
        path = item.get("path")
        events.append((
            "file_added", "integrity_checker", path,
            "File added: {}".format(path), "medium",
            {"current_hash": item.get("current_hash")},
        ))

    for item in _items(integrity_result, "deleted"):
        path = item.get("path")
        events.append((
            "file_deleted", "integrity_checker", path,
            "File deleted: {}".format(path), "high",
            {"baseline_hash": item.get("baseline_hash")},
        ))

    for item in _items(integrity_result, "renamed"):
        old_path = item.get("old_path")
        new_path = item.get("new_path")
        events.append((
            "file_renamed", "integrity_checker", new_path,
            "File renamed: {} -> {}".format(old_path, new_path), "medium",
            {"old_path": old_path, "new_path": new_path, "sha256": item.get("sha256")},
        ))

    # FR-03: suspicious findings – suspicious_files is the primary source.
    # executable_files / newly_added_files are only cross-referenced to
    # enrich the event; they are never logged as separate duplicates.
    if suspicious_result is not None:
        if suspicious_status == "invalid_directory":
            events.append((
                "invalid_directory", "suspicious_detector", None,
                "Invalid or unavailable monitoring directory.", "medium",
                {"suspicious_status": suspicious_status},
            ))
        else:
            executable_paths = {
                item.get("path") for item in _items(suspicious_result, "executable_files")
            }
            newly_added_paths = {
                item.get("path") for item in _items(suspicious_result, "newly_added_files")
            }
            for item in _items(suspicious_result, "suspicious_files"):
                path = item.get("path")
                reasons = item.get("reasons") if isinstance(item.get("reasons"), list) else []
                severity = item.get("severity")
                if severity not in SEVERITIES:
                    severity = "medium"
                events.append((
                    "suspicious_file", "suspicious_detector", path,
                    "Suspicious file detected: {}".format(path), severity,
                    {
                        "extension": item.get("extension"),
                        "reasons": reasons,
                        "executable": path in executable_paths,
                        "newly_added": path in newly_added_paths,
                    },
                ))

            # FR-04: suspicious-detector errors (with their source)
            for item in _items(suspicious_result, "errors"):
                events.append((
                    "scan_error", "suspicious_detector", item.get("path"),
                    "Suspicious detector error: {}".format(item.get("message")), "medium",
                    {"message": item.get("message")},
                ))

    # FR-04: integrity-checker errors.  For the two special statuses the
    # dedicated events above already describe the failure precisely, and
    # the modules' error arrays contain exactly that failure, so they are
    # not duplicated as generic scan_error events.
    if integrity_status not in ("baseline_unavailable", "invalid_directory"):
        for item in _items(integrity_result, "errors"):
            events.append((
                "scan_error", "integrity_checker", item.get("path"),
                "Integrity checker error: {}".format(item.get("message")), "medium",
                {"message": item.get("message")},
            ))

    return events


def log_scan(integrity_result, suspicious_result=None):
    """Persist one scan and its associated activity events (FR-01..FR-04).

    The scan row and all of its events are written in a single
    transaction, so a partially written scan can never occur.

    Returns:
        {"scan_id": int, "status": str, "overall_status": str}
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

    database.init_db()
    conn = database.get_connection()

    integrity_status = _status(integrity_result) or "unknown"
    suspicious_status = _status(suspicious_result)
    baseline_status = derive_baseline_status(integrity_result)
    overall_status = derive_overall_status(integrity_result, suspicious_result)
    scan_time = _scan_time(integrity_result)
    created_at = database.now_iso()

    directory = integrity_result.get("directory")
    if not isinstance(directory, str) or not directory:
        directory = "unknown"

    events = _build_events(
        integrity_result, suspicious_result, integrity_status,
        suspicious_status, baseline_status, overall_status,
    )

    # Single transaction: scan row + all events (TRD 7.3 / 10.5).
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (
                directory, scan_time, integrity_status, suspicious_status,
                baseline_status, overall_status, integrity_summary,
                suspicious_summary, integrity_result, suspicious_result,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                directory,
                scan_time,
                integrity_status,
                suspicious_status,
                baseline_status,
                overall_status,
                json.dumps(_summary(integrity_result)),
                json.dumps(_summary(suspicious_result)) if suspicious_result is not None else None,
                json.dumps(integrity_result),
                json.dumps(suspicious_result) if suspicious_result is not None else None,
                created_at,
            ),
        )
        scan_id = cursor.lastrowid

        conn.executemany(
            """
            INSERT INTO activity_logs (
                scan_id, event_type, source, file_path, description,
                severity, details, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    scan_id, event_type, source, file_path, description,
                    severity, json.dumps(details) if details is not None else None,
                    scan_time,
                )
                for (event_type, source, file_path, description, severity, details) in events
            ],
        )

    return {
        "scan_id": scan_id,
        "status": integrity_status,
        "overall_status": overall_status,
    }


def append_scan_event(scan_id, event_type, source, description,
                      severity="medium", file_path=None, details=None,
                      timestamp=None):
    """Append a single activity event to an already recorded scan.

    Used by the scan orchestrator to keep unexpected workflow-stage
    failures (e.g. an alert- or report-generation error) visible in the
    activity log of the affected scan (FR-04).  The scan itself must
    already exist; the event is written in its own transaction so it can
    never corrupt the original scan record.

    Returns the created event as a dictionary (see ``get_event_by_id``).
    """
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")
    if event_type not in EVENT_TYPES:
        raise ValueError(
            "Unsupported event_type '{}'. Supported values: {}".format(
                event_type, ", ".join(EVENT_TYPES)
            )
        )
    if source not in SOURCES:
        raise ValueError(
            "Unsupported source '{}'. Supported values: {}".format(
                source, ", ".join(SOURCES)
            )
        )
    if severity not in SEVERITIES:
        raise ValueError(
            "Unsupported severity '{}'. Supported values: {}".format(
                severity, ", ".join(SEVERITIES)
            )
        )
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description must be a non-empty string")

    database.init_db()
    conn = database.get_connection()

    scan_row = conn.execute(
        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if scan_row is None:
        raise ValueError(
            "No recorded scan with id {}. Call log_scan() before "
            "appending events.".format(scan_id)
        )

    event_time = timestamp if isinstance(timestamp, str) and timestamp else database.now_iso()

    with conn:
        cursor = conn.execute(
            """
            INSERT INTO activity_logs (
                scan_id, event_type, source, file_path, description,
                severity, details, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id, event_type, source, file_path, description.strip(),
                severity, json.dumps(details) if details is not None else None,
                event_time,
            ),
        )
        event_id = cursor.lastrowid

    return get_event_by_id(event_id)


# ---------------------------------------------------------------------------
# FR-05 / FR-06: retrieval
# ---------------------------------------------------------------------------

_SCAN_SELECT = """
SELECT s.*,
       (SELECT COUNT(*) FROM activity_logs e WHERE e.scan_id = s.scan_id) AS event_count,
       (SELECT COUNT(*) FROM alerts a WHERE a.scan_id = s.scan_id)       AS alert_count
FROM scans s
"""


def _row_to_scan(row, include_results=False):
    integrity_summary = _json_loads(row["integrity_summary"], {})
    suspicious_summary = _json_loads(row["suspicious_summary"], None)

    error_count = 0
    for summary in (integrity_summary, suspicious_summary):
        if isinstance(summary, dict):
            try:
                error_count += int(summary.get("errors") or 0)
            except (TypeError, ValueError):
                pass

    scan = {
        "scan_id": row["scan_id"],
        "directory": row["directory"],
        "scan_time": row["scan_time"],
        "integrity_status": row["integrity_status"],
        "suspicious_status": row["suspicious_status"],
        "baseline_status": row["baseline_status"],
        "overall_status": row["overall_status"],
        "integrity_summary": integrity_summary,
        "suspicious_summary": suspicious_summary,
        "created_at": row["created_at"],
        "event_count": row["event_count"],
        "alert_count": row["alert_count"],
        "error_count": error_count,
    }
    if include_results:
        scan["integrity_result"] = _json_loads(row["integrity_result"], None)
        scan["suspicious_result"] = _json_loads(row["suspicious_result"], None)
    return scan


def _row_to_event(row):
    return {
        "event_id": row["event_id"],
        "scan_id": row["scan_id"],
        "event_type": row["event_type"],
        "source": row["source"],
        "file_path": row["file_path"],
        "description": row["description"],
        "severity": row["severity"],
        "details": _json_loads(row["details"], None),
        "timestamp": row["timestamp"],
    }


def get_scan_history(limit=50, offset=0):
    """Return historical scan records with pagination (FR-05)."""
    limit, offset = _validate_pagination(limit, offset)
    database.init_db()
    conn = database.get_connection()

    total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    rows = conn.execute(
        _SCAN_SELECT + " ORDER BY s.scan_id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall()

    return {
        "items": [_row_to_scan(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def get_scan_by_id(scan_id):
    """Return one scan record (including the original results) or None."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")
    database.init_db()
    conn = database.get_connection()

    row = conn.execute(_SCAN_SELECT + " WHERE s.scan_id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    return _row_to_scan(row, include_results=True)


def get_scan_events(scan_id):
    """Return all activity events associated with a scan (FR-06)."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")
    database.init_db()
    conn = database.get_connection()

    rows = conn.execute(
        "SELECT * FROM activity_logs WHERE scan_id = ? ORDER BY event_id ASC",
        (scan_id,),
    ).fetchall()
    return [_row_to_event(row) for row in rows]


def get_event_by_id(event_id):
    """Return a single activity event or None."""
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        raise ValueError("event_id must be an integer")
    database.init_db()
    conn = database.get_connection()

    row = conn.execute(
        "SELECT * FROM activity_logs WHERE event_id = ?", (event_id,)
    ).fetchone()
    return _row_to_event(row) if row is not None else None


def get_activity_logs(event_type=None, start_date=None, end_date=None,
                      scan_id=None, severity=None, limit=100, offset=0):
    """Return filtered and paginated activity logs (FR-06).

    Filters:
      event_type – exact event type (see EVENT_TYPES)
      start_date / end_date – 'YYYY-MM-DD' or ISO 8601 timestamp
      scan_id    – only events of this scan
      severity   – exact severity
    """
    limit, offset = _validate_pagination(limit, offset)
    database.init_db()
    conn = database.get_connection()

    clauses = []
    params = []
    if event_type:
        clauses.append("event_type = ?")
        params.append(str(event_type))
    if severity:
        clauses.append("severity = ?")
        params.append(str(severity))
    if scan_id is not None:
        try:
            clauses.append("scan_id = ?")
            params.append(int(scan_id))
        except (TypeError, ValueError):
            raise ValueError("scan_id must be an integer")
    start = _normalize_date(start_date, end_of_day=False)
    if start:
        # datetime() normalizes timezone offsets so the comparison is correct
        # even when stored timestamps carry different UTC offsets.
        clauses.append("datetime(timestamp) >= datetime(?)")
        params.append(start)
    end = _normalize_date(end_date, end_of_day=True)
    if end:
        clauses.append("datetime(timestamp) <= datetime(?)")
        params.append(end)

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    total = conn.execute(
        "SELECT COUNT(*) FROM activity_logs" + where, params
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT * FROM activity_logs" + where
        + " ORDER BY datetime(timestamp) DESC, event_id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()

    return {
        "items": [_row_to_event(row) for row in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }
