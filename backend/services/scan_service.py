"""Scan orchestration service (backend/services/scan_service.py).

Coordinates the complete scan flow required by the TRD (section 8):

1. ``check_integrity()``            – integrity checker
2. ``check_suspicious_files()``     – suspicious file detector
3. ``log_scan()``                   – activity logger
4. ``generate_alerts()``            – alerts
5. ``generate_report()``            – reports

The service contains NO logging, alert or reporting logic of its own –
it only calls the detection, logging, alert and reporting functions and
makes sure that every result set is associated with a single scan ID.
"""

from integrity_checker import check_integrity
from suspicious_detector import check_suspicious_files
from baseline import create_baseline as _create_signed_baseline

from activity_logger import (
    derive_baseline_status,
    log_scan,
)
from alerts import generate_alerts
from report_generator import generate_report


def run_scan(directory, baseline_file="baseline.json"):
    """Run one complete scan and return a compact summary.

    Every scan attempt is recorded, including failed attempts: if
    ``check_integrity()`` reports an invalid directory or an unavailable
    baseline, the failure itself is logged, alerted and reported.
    """
    directory = str(directory or "").strip()
    if not directory:
        raise ValueError("directory is required")
    baseline_file = str(baseline_file or "baseline.json").strip() or "baseline.json"

    # Stage 1: integrity check
    integrity_result = check_integrity(directory, baseline_file)

    # Stage 2: suspicious detection
    suspicious_result = check_suspicious_files(directory, integrity_result)

    # Stage 3: record the scan attempt and its events
    scan_record = log_scan(integrity_result, suspicious_result)
    scan_id = scan_record["scan_id"]

    # Stage 4: alerts
    alerts = generate_alerts(integrity_result, suspicious_result, scan_id)

    # Stage 5: report
    report = generate_report(integrity_result, suspicious_result, alerts, scan_id)

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
        "alerts_generated": len(alerts),
        "report_id": report.get("report_id"),
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
