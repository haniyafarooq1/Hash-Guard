"""Hash Guard – Report Generator (report_generator.py).

Creates a complete JSON snapshot of an individual scan (FR-17..FR-22):
scan information, integrity summary and details, suspicious-file summary
and details, the alerts generated for the scan, all errors and an
easy-to-understand overall assessment.

Guarantees required by the TRD:
* A report is generated for EVERY recorded scan attempt, including
  failed ones (FR-17).
* An unsuccessful or incomplete scan is never labelled clean (FR-17,
  10.2) – the overall assessment stored by the activity logger is reused,
  it is never re-derived more optimistically.
* The report is a SNAPSHOT: later alert-status changes never rewrite the
  historical report contents (FR-22, 10.6).
* PDF export (optional feature, implemented) reuses exactly the same
  report data; it never recalculates or modifies scan findings (FR-21).
* The stored snapshot uses a controlled UPSERT: re-generating a report
  for a scan replaces its snapshot instead of creating duplicates.
* Failure isolation (10.5): report generation is a separate transaction
  from scan/event logging, so a report failure leaves the recorded scan
  and events intact.
"""

import json
from pathlib import Path
from xml.sax.saxutils import escape

from backend.storage import database


class ReportNotFoundError(LookupError):
    """Raised when exporting a report that has not been generated."""


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


def _status_of(result):
    """Human-readable status of a stage result ('not_run' when absent)."""
    if isinstance(result, dict):
        status = result.get("status")
        if isinstance(status, str) and status:
            return status
    return "not_run"


def _copy_summary(result):
    if not isinstance(result, dict):
        return {}
    summary = result.get("summary")
    return dict(summary) if isinstance(summary, dict) else {}


def _count(result, key):
    value = _copy_summary(result).get(key)
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _json_loads(text, default):
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Assessment text (FR-18 section H)
# ---------------------------------------------------------------------------

def _assessment_text(status, integrity_result, suspicious_result):
    changed = sum(
        _count(integrity_result, key)
        for key in ("modified", "added", "deleted", "renamed")
    )
    suspicious = _count(suspicious_result, "suspicious_files") if suspicious_result else 0
    errors = _count(integrity_result, "errors") + (
        _count(suspicious_result, "errors") if suspicious_result else 0
    )

    if status == "clean":
        return (
            "The scan completed successfully. No file changes or suspicious "
            "files were detected, and no errors were reported."
        )
    if status == "findings_detected":
        return (
            "The scan completed and detected {} file change(s) and {} "
            "suspicious file(s). Review the findings in this report.".format(
                changed, suspicious
            )
        )
    if status == "completed_with_errors":
        return (
            "The scan completed but {} error(s) were reported. The findings "
            "in this report may be incomplete.".format(errors)
        )
    if status == "incomplete":
        return (
            "The scan did not complete: the integrity check reported "
            "'{}' and the suspicious-file detection reported '{}'. A scan "
            "is only clean when both checks complete successfully, so "
            "this result must not be treated as clean.".format(
                _status_of(integrity_result), _status_of(suspicious_result)
            )
        )
    if status == "incomplete":
        return (
            "The scan did not complete: the integrity check reported "
            "'{}' and the suspicious-file detection reported '{}'. A scan "
            "is only clean when both checks complete successfully, so "
            "this result must not be treated as clean.".format(
                _status_of(integrity_result), _status_of(suspicious_result)
            )
        )
    if status == "baseline_unavailable":
        return (
            "The baseline could not be loaded or authenticated, so the "
            "file-integrity comparison was not performed. This scan must "
            "not be treated as a clean result."
        )
    if status == "invalid_directory":
        return (
            "The monitoring directory is invalid or unavailable, so the "
            "scan could not be performed."
        )
    return "The scan finished with an unrecognised assessment ({}).".format(status)


def _collect_errors(integrity_result, suspicious_result):
    """All errors, with their source preserved (FR-18 section G)."""
    errors = []
    for item in _items(integrity_result, "errors"):
        errors.append({
            "source": "integrity_checker",
            "path": item.get("path"),
            "message": item.get("message"),
        })
    if suspicious_result is not None:
        for item in _items(suspicious_result, "errors"):
            errors.append({
                "source": "suspicious_detector",
                "path": item.get("path"),
                "message": item.get("message"),
            })
    return errors


# ---------------------------------------------------------------------------
# FR-17 .. FR-20, FR-22: generation and persistence
# ---------------------------------------------------------------------------

def generate_report(integrity_result, suspicious_result, alerts, scan_id):
    """Generate and persist a report snapshot for one scan.

    The scan must already be recorded (``log_scan()``); the stored scan
    row is the authoritative source for the preserved statuses and the
    derived assessments, so the report can never disagree with the
    recorded history.
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
    if alerts is not None and not isinstance(alerts, list):
        raise ValueError("alerts must be the list returned by generate_alerts() or None")
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")

    database.init_db()
    conn = database.get_connection()

    scan_row = conn.execute(
        "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    if scan_row is None:
        raise ValueError(
            "No recorded scan with id {}. Call log_scan() before generating "
            "a report.".format(scan_id)
        )

    alert_list = [a for a in (alerts or []) if isinstance(a, dict)]
    generated_at = database.now_iso()

    report = {
        "scan_id": scan_id,
        "generated_at": generated_at,
        # A. Scan information
        "scan_info": {
            "scan_id": scan_id,
            "directory": scan_row["directory"],
            "scan_time": scan_row["scan_time"],
            "integrity_status": scan_row["integrity_status"],
            "suspicious_status": scan_row["suspicious_status"],
            "baseline_status": scan_row["baseline_status"],
            "overall_status": scan_row["overall_status"],
        },
        # B. Integrity summary (preserved exactly as reported)
        "integrity_summary": _copy_summary(integrity_result),
        # C. Integrity details
        "integrity_details": {
            "modified": [
                {
                    "path": item.get("path"),
                    "baseline_hash": item.get("baseline_hash"),
                    "current_hash": item.get("current_hash"),
                }
                for item in _items(integrity_result, "modified")
            ],
            "added": [
                {"path": item.get("path"), "current_hash": item.get("current_hash")}
                for item in _items(integrity_result, "added")
            ],
            "deleted": [
                {"path": item.get("path"), "baseline_hash": item.get("baseline_hash")}
                for item in _items(integrity_result, "deleted")
            ],
            "renamed": [
                {
                    "old_path": item.get("old_path"),
                    "new_path": item.get("new_path"),
                    "sha256": item.get("sha256"),
                }
                for item in _items(integrity_result, "renamed")
            ],
        },
        # D. Suspicious file summary
        "suspicious_summary": (
            _copy_summary(suspicious_result) if suspicious_result is not None else None
        ),
        # E. Suspicious file details
        "suspicious_details": [
            {
                "path": item.get("path"),
                "extension": item.get("extension"),
                "reasons": item.get("reasons") if isinstance(item.get("reasons"), list) else [],
                "severity": item.get("severity"),
            }
            for item in (
                _items(suspicious_result, "suspicious_files")
                if suspicious_result is not None else []
            )
        ],
        # F. Security alerts (snapshot as they existed at generation time)
        "alerts": [
            {
                "alert_id": alert.get("alert_id"),
                "title": alert.get("title"),
                "description": alert.get("description"),
                "severity": alert.get("severity"),
                "category": alert.get("category"),
                "file_path": alert.get("file_path"),
                "status": alert.get("status"),
                "timestamp": alert.get("timestamp"),
            }
            for alert in alert_list
        ],
        # G. Errors
        "errors": _collect_errors(integrity_result, suspicious_result),
        # H. Overall assessment
        "overall_assessment": {
            "status": scan_row["overall_status"],
            "summary": _assessment_text(
                scan_row["overall_status"], integrity_result, suspicious_result
            ),
        },
    }

    # Controlled UPSERT: one report per scan, refreshed in place.
    with conn:
        conn.execute(
            """
            INSERT INTO reports (scan_id, report_data, generated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(scan_id) DO UPDATE SET
                report_data = excluded.report_data,
                generated_at = excluded.generated_at
            """,
            (scan_id, json.dumps(report), generated_at),
        )

    row = conn.execute(
        "SELECT report_id FROM reports WHERE scan_id = ?", (scan_id,)
    ).fetchone()
    report["report_id"] = row["report_id"]
    return report


def get_report(scan_id):
    """Retrieve the stored report for a scan, or None (FR-22)."""
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        raise ValueError("scan_id must be an integer")
    database.init_db()
    conn = database.get_connection()

    row = conn.execute(
        "SELECT report_id, scan_id, report_data, generated_at FROM reports "
        "WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()
    if row is None:
        return None

    report = _json_loads(row["report_data"], {})
    report["report_id"] = row["report_id"]
    report["scan_id"] = row["scan_id"]
    report["generated_at"] = row["generated_at"]
    return report


def list_reports(limit=50, offset=0):
    """List stored report snapshots (newest first) with pagination."""
    try:
        limit = int(limit)
        offset = int(offset)
    except (TypeError, ValueError):
        raise ValueError("limit and offset must be integers")
    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    if offset < 0:
        raise ValueError("offset must be 0 or greater")

    database.init_db()
    conn = database.get_connection()

    total = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    rows = conn.execute(
        """
        SELECT r.report_id, r.scan_id, r.generated_at,
               s.directory, s.scan_time, s.integrity_status,
               s.suspicious_status, s.baseline_status, s.overall_status,
               s.integrity_summary, s.suspicious_summary
        FROM reports r JOIN scans s ON s.scan_id = r.scan_id
        ORDER BY r.report_id DESC LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()

    items = []
    for row in rows:
        items.append({
            "report_id": row["report_id"],
            "scan_id": row["scan_id"],
            "generated_at": row["generated_at"],
            "directory": row["directory"],
            "scan_time": row["scan_time"],
            "integrity_status": row["integrity_status"],
            "suspicious_status": row["suspicious_status"],
            "baseline_status": row["baseline_status"],
            "overall_status": row["overall_status"],
            "integrity_summary": _json_loads(row["integrity_summary"], {}),
            "suspicious_summary": _json_loads(row["suspicious_summary"], None),
        })
    return {"items": items, "total": total, "limit": limit, "offset": offset}


# ---------------------------------------------------------------------------
# FR-20 / FR-21: exports
# ---------------------------------------------------------------------------

def export_report_json(scan_id, output_path=None):
    """Export a stored report as a JSON file. Returns the path written."""
    report = get_report(scan_id)
    if report is None:
        raise ReportNotFoundError(
            "No report has been generated for scan {}.".format(scan_id)
        )
    if output_path is None:
        output_path = "hashguard_report_scan_{}.json".format(scan_id)
    path = Path(output_path)
    if str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return path


def export_report_pdf(scan_id, output_path=None):
    """Export a stored report as a PDF file. Returns the path written.

    The PDF is rendered from exactly the same stored report data; no scan
    findings are recalculated or modified (FR-21).
    """
    report = get_report(scan_id)
    if report is None:
        raise ReportNotFoundError(
            "No report has been generated for scan {}.".format(scan_id)
        )
    if output_path is None:
        output_path = "hashguard_report_scan_{}.pdf".format(scan_id)

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import (
            Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as error:  # pragma: no cover - environment specific
        raise RuntimeError(
            "PDF export requires the 'reportlab' package "
            "(pip install reportlab)."
        ) from error

    # ------------------------------------------------------------------
    # Styles
    # ------------------------------------------------------------------
    body = ParagraphStyle("Body", fontName="Helvetica", fontSize=9, leading=12)
    small = ParagraphStyle(
        "Small", fontName="Helvetica", fontSize=7, leading=9, wordWrap="CJK"
    )
    header_cell = ParagraphStyle(
        "HeaderCell", fontName="Helvetica-Bold", fontSize=8, leading=10
    )
    heading = ParagraphStyle(
        "Heading", fontName="Helvetica-Bold", fontSize=12, leading=15,
        spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#0e7490"),
    )
    title = ParagraphStyle(
        "Title", fontName="Helvetica-Bold", fontSize=17, leading=21, spaceAfter=2,
    )
    subtitle = ParagraphStyle(
        "Subtitle", fontName="Helvetica", fontSize=9, leading=12,
        textColor=colors.HexColor("#555555"), spaceAfter=10,
    )

    def text(value):
        return escape(str(value)) if value is not None else "-"

    def cell(value):
        return Paragraph(text(value), small)

    def make_table(headers, rows, col_widths):
        """Standard table with a bold header row; empty -> note paragraph."""
        if not rows:
            return Paragraph("None reported.", body)
        data = [
            [Paragraph("<b>{}</b>".format(text(h)), header_cell) for h in headers]
        ] + list(rows)
        table = Table(data, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e0f2fe")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return table

    def make_info_table(rows):
        table = Table(rows, colWidths=[1.9 * inch, 4.6 * inch])
        table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        return table

    story = []
    scan_info = report.get("scan_info", {})

    # Title
    story.append(Paragraph("Hash Guard - Security Report", title))
    story.append(Paragraph(
        "Scan #{} &nbsp;|&nbsp; generated {} &nbsp;|&nbsp; overall: {}".format(
            text(report.get("scan_id")),
            text(report.get("generated_at")),
            text(scan_info.get("overall_status")),
        ),
        subtitle,
    ))

    # A. Scan information
    story.append(Paragraph("Scan Information", heading))
    story.append(make_info_table([
        [Paragraph("Scan ID", body), cell(report.get("scan_id"))],
        [Paragraph("Monitored directory", body), cell(scan_info.get("directory"))],
        [Paragraph("Scan timestamp", body), cell(scan_info.get("scan_time"))],
        [Paragraph("Integrity status", body), cell(scan_info.get("integrity_status"))],
        [Paragraph("Suspicious-detector status", body),
         cell(scan_info.get("suspicious_status") or "not run")],
        [Paragraph("Baseline assessment", body), cell(scan_info.get("baseline_status"))],
        [Paragraph("Overall assessment", body), cell(scan_info.get("overall_status"))],
    ]))

    # H. Overall assessment (executive summary, shown early)
    story.append(Paragraph("Overall Assessment", heading))
    assessment = report.get("overall_assessment", {})
    story.append(Paragraph(
        "<b>{}</b> - {}".format(
            text(assessment.get("status", "unknown")),
            text(assessment.get("summary", "")),
        ),
        body,
    ))

    # B. Integrity summary
    story.append(Paragraph("Integrity Summary", heading))
    integrity_summary = report.get("integrity_summary", {}) or {}
    summary_table = Table(
        [
            [Paragraph(label, body), cell(integrity_summary.get(key, 0))]
            for label, key in (
                ("Modified", "modified"), ("Added", "added"),
                ("Deleted", "deleted"), ("Renamed", "renamed"),
                ("Errors", "errors"),
            )
        ],
        colWidths=[2.0 * inch, 1.0 * inch],
    )
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(summary_table)

    # C. Integrity details
    story.append(Paragraph("Integrity Details", heading))
    details = report.get("integrity_details", {}) or {}

    story.append(Paragraph("Modified files", body))
    story.append(make_table(
        ("Relative path", "Baseline SHA-256", "Current SHA-256"),
        [
            (cell(item.get("path")), cell(item.get("baseline_hash")),
             cell(item.get("current_hash")))
            for item in details.get("modified", [])
        ],
        (1.7 * inch, 2.4 * inch, 2.4 * inch),
    ))
    story.append(Paragraph("Added files", body))
    story.append(make_table(
        ("Relative path", "Current SHA-256"),
        [
            (cell(item.get("path")), cell(item.get("current_hash")))
            for item in details.get("added", [])
        ],
        (2.4 * inch, 4.1 * inch),
    ))
    story.append(Paragraph("Deleted files", body))
    story.append(make_table(
        ("Relative path", "Previous SHA-256"),
        [
            (cell(item.get("path")), cell(item.get("baseline_hash")))
            for item in details.get("deleted", [])
        ],
        (2.4 * inch, 4.1 * inch),
    ))
    story.append(Paragraph("Renamed files", body))
    story.append(make_table(
        ("Previous path", "New path", "Matching SHA-256"),
        [
            (cell(item.get("old_path")), cell(item.get("new_path")),
             cell(item.get("sha256")))
            for item in details.get("renamed", [])
        ],
        (1.8 * inch, 1.8 * inch, 2.9 * inch),
    ))

    # D / E. Suspicious files
    story.append(Paragraph("Suspicious Files", heading))
    suspicious_summary = report.get("suspicious_summary") or {}
    suspicious_table = Table(
        [
            [Paragraph(label, body), cell(suspicious_summary.get(key, 0))]
            for label, key in (
                ("Suspicious files", "suspicious_files"),
                ("Newly added files", "newly_added_files"),
                ("Executable files", "executable_files"),
                ("Detection errors", "errors"),
            )
        ],
        colWidths=[2.0 * inch, 1.2 * inch],
    )
    suspicious_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
    ]))
    story.append(suspicious_table)
    story.append(Spacer(1, 8))

    suspicious_details = report.get("suspicious_details", []) or []
    if suspicious_details:
        story.append(make_table(
            ("File path", "Extension", "Severity", "Detection reasons"),
            [
                (
                    cell(item.get("path")),
                    cell(item.get("extension")),
                    cell(item.get("severity")),
                    cell("; ".join(
                        str(reason) for reason in (item.get("reasons") or [])
                    )),
                )
                for item in suspicious_details
            ],
            (2.0 * inch, 0.7 * inch, 0.8 * inch, 3.0 * inch),
        ))
    else:
        story.append(Paragraph("No suspicious files were reported.", body))

    # F. Security alerts
    story.append(Paragraph("Security Alerts", heading))
    report_alerts = report.get("alerts", []) or []
    if report_alerts:
        for alert in report_alerts:
            story.append(Paragraph(
                "<b>{}</b> [{} / {} / {}]{}".format(
                    text(alert.get("title")),
                    text(alert.get("severity")),
                    text(alert.get("category")),
                    text(alert.get("status")),
                    " - file: {}".format(text(alert.get("file_path")))
                    if alert.get("file_path") else "",
                ),
                body,
            ))
            story.append(Paragraph(text(alert.get("description")), small))
            story.append(Spacer(1, 4))
    else:
        story.append(
            Paragraph("No security alerts were generated for this scan.", body)
        )

    # G. Errors
    story.append(Paragraph("Errors", heading))
    report_errors = report.get("errors", []) or []
    if report_errors:
        story.append(make_table(
            ("Source", "Affected path", "Error message"),
            [
                (cell(item.get("source")), cell(item.get("path")),
                 cell(item.get("message")))
                for item in report_errors
            ],
            (1.4 * inch, 2.2 * inch, 2.9 * inch),
        ))
    else:
        story.append(Paragraph("No errors were reported.", body))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "Report generated by Hash Guard (reporting layer). "
        "This document is a snapshot of scan #{} taken at {} and reflects "
        "the data as it existed at generation time.".format(
            text(report.get("scan_id")), text(report.get("generated_at"))
        ),
        small,
    ))

    path = Path(output_path)
    if str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)
    document = SimpleDocTemplate(
        str(path), pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        title="Hash Guard Security Report - Scan {}".format(report.get("scan_id")),
    )
    document.build(story)
    return path
