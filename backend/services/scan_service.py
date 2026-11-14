"""Scan orchestration service (backend/services/scan_service.py).

Coordinates the complete scan flow required by the TRD (section 8):

1. ``check_integrity()``            – integrity checker
2. ``check_suspicious_files()``     – suspicious file detector
3. ``log_scan()``                   – activity logger
4. ``generate_alerts()``            – alerts
5. ``generate_report()``            – reports

Stage isolation rules (TRD section 8.3):

* An unexpected failure of a detection stage is captured in a synthetic
  result (status ``failed``) so the scan attempt is still recorded.  A
  scan whose detection stages did not both complete is assessed as
  ``incomplete`` by the activity logger – never as a clean result.
* A failure of the alert stage never prevents the report stage, and a
  failure of the report stage never removes the already stored scan,
  events and alerts.
* Every stage failure is appended to the scan's activity log, so
  unexpected failures remain visible in the history.
* A failure of the recording stage itself (the scan cannot be stored at
  all) propagates to the caller.

The service contains NO logging, alert or reporting logic of its own –
it only calls the detection, logging, alert and reporting functions and
makes sure that every result set is associated with a single scan ID.
"""

from integrity_checker import check_integrity
from suspicious_detector import check_suspicious_files
from baseline import create_baseline as _create_signed_baseline

from activity_logger import (
    append_scan_event,
    derive_baseline_status,
    log_scan,
)
from alerts import generate_alerts
from backend.storage.database import now_iso
from report_generator import generate_report


def _stage_failure_result(kind, directory, error):
    """Synthetic result used when a detection stage fails unexpectedly.

    Shaped exactly like the result the failed stage would have returned,
    with status ``failed`` and the exception recorded as the stage's
    only error.  The activity logger derives ``incomplete`` from this
    status, so a crashed stage can never produce a clean scan.
    """
    message = "{} stage failed unexpectedly: {}".format(
        "Integrity check" if kind == "integrity" else "Suspicious detection",
        error,
    )
    if kind == "integrity":
        return {
            "status": "failed",
            "scan_time": now_iso(),
            "directory": str(directory),
            "summary": {
                "modified": 0, "added": 0, "deleted": 0,
                "renamed": 0, "errors": 1,
            },
            "modified": [], "added": [], "deleted": [], "renamed": [],
            "errors": [{"path": str(directory), "message": message}],
        }
    return {
        "status": "failed",
        "scan_time": now_iso(),
        "directory": str(directory),
        "summary": {
            "suspicious_files": 0, "newly_added_files": 0,
            "executable_files": 0, "errors": 1,
        },
        "suspicious_files": [], "newly_added_files": [],
        "executable_files": [],
        "errors": [{"path": str(directory), "message": message}],
    }


def _record_stage_failure(scan_id, stage, error):
    """Best effort: append a workflow-stage failure to the activity log.

    Returns True when the failure was recorded; if even this recording
    fails (e.g. the database is gone) the remaining stages still run and
    the failure is reported in the returned stage_failures list.
    """
    try:
        append_scan_event(
            scan_id,
            event_type="scan_error",
            source="system",
            description="{} stage failed: {}".format(stage, error),
            severity="high",
            details={"stage": stage, "error": str(error)},
        )
        return True
    except Exception:  # noqa: BLE001 - never mask the scan result
        return False


def run_scan(directory, baseline_file="baseline.json"):
    """Run one complete scan and return a compact summary.

    Every scan attempt is recorded, including failed attempts: if
    ``check_integrity()`` reports an invalid directory or an unavailable
    baseline, the failure itself is logged, alerted and reported.  Each
    workflow stage is isolated from the next one, so a failure in a late
    stage (alerts, report) never destroys the results of the earlier
    stages – and never leaves the scan looking clean.
    """
    directory = str(directory or "").strip()
    if not directory:
        raise ValueError("directory is required")
    baseline_file = str(baseline_file or "baseline.json").strip() or "baseline.json"

    stage_failures = []

    # Stage 1: integrity check.  An unexpected crash is captured in a
    # synthetic "failed" result so the attempt is still recorded.
    try:
        integrity_result = check_integrity(directory, baseline_file)
        if not isinstance(integrity_result, dict):
            raise ValueError(
                "check_integrity() did not return a result dictionary"
            )
    except Exception as error:  # noqa: BLE001 - stage isolation
        integrity_result = _stage_failure_result("integrity", directory, error)
        stage_failures.append(("integrity_check", error))

    # Stage 2: suspicious detection.  Runs even after an integrity
    # failure so that as much information as possible is collected.
    try:
        suspicious_result = check_suspicious_files(directory, integrity_result)
        if not isinstance(suspicious_result, dict):
            raise ValueError(
                "check_suspicious_files() did not return a result dictionary"
            )
    except Exception as error:  # noqa: BLE001 - stage isolation
        suspicious_result = _stage_failure_result("suspicious", directory, error)
        stage_failures.append(("suspicious_detection", error))

    # Stage 3: record the scan attempt and its events.  If THIS stage
    # fails there is nothing to attach later results to, so the error
    # propagates to the caller.
    scan_record = log_scan(integrity_result, suspicious_result)
    scan_id = scan_record["scan_id"]

    # Keep the raw stage failures visible in the activity log.
    for stage, error in stage_failures:
        _record_stage_failure(scan_id, stage, error)

    # Stage 4: alerts.  A failure here must not stop the report stage;
    # the report receives a clearly labelled placeholder entry instead
    # so readers can see why the alert list is absent.
    alerts = []
    alert_stage_failed = False
    try:
        alerts = generate_alerts(integrity_result, suspicious_result, scan_id)
    except Exception as error:  # noqa: BLE001 - stage isolation
        alert_stage_failed = True
        stage_failures.append(("alert_generation", error))
        _record_stage_failure(scan_id, "alert_generation", error)
        alerts = [{
            "alert_id": None,
            "title": "Alert Generation Failed",
            "description": (
                "Alerts could not be generated for this scan ({}). The "
                "scan findings above are still valid; only the alert "
                "processing failed.".format(error)
            ),
            "severity": "critical",
            "category": "system",
            "file_path": None,
            "status": "unread",
            "timestamp": now_iso(),
        }]

    # Stage 5: report.  Attempted even when the alert stage failed.
    report_id = None
    try:
        report = generate_report(
            integrity_result, suspicious_result, alerts, scan_id
        )
        report_id = report.get("report_id")
    except Exception as error:  # noqa: BLE001 - stage isolation
        stage_failures.append(("report_generation", error))
        _record_stage_failure(scan_id, "report_generation", error)

    return {
        "scan_id": scan_id,
        "directory": integrity_result.get("directory", directory),
        "scan_time": integrity_result.get("scan_time"),
        "integrity_status": scan_record["status"],
        "suspicious_status": suspicious_result.get("status"),
        "baseline_status": derive_baseline_status(integrity_result),
        "overall_status": scan_record["overall_status"],
        "integrity_summary": integrity_result.get("summary", {}),
        "suspicious_summary": suspicious_result.get("summary", {}),
        "alerts_generated": 0 if alert_stage_failed else len(alerts),
        "report_id": report_id,
        "stage_failures": [
            {"stage": stage, "error": str(error)}
            for stage, error in stage_failures
        ],
    }


def create_monitored_baseline(directory, baseline_file="baseline.json"):
    """Create (and sign) a baseline using the baseline module."""
    directory = str(directory or "").strip()
    if not directory:
        raise ValueError("directory is required")
    baseline_file = str(baseline_file or "baseline.json").strip() or "baseline.json"

    success = _create_signed_baseline(directory, baseline_file)
    return {
        "success": bool(success),
        "directory": directory,
        "baseline_file": baseline_file,
    }
