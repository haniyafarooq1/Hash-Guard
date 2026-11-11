"""Report endpoints (TRD section 8.1).

GET /api/reports                    – list stored report snapshots
GET /api/reports/{scan_id}          – retrieve the JSON report of a scan
GET /api/reports/{scan_id}/export   – download a report (format=json|pdf)
"""

import os
import tempfile

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from report_generator import (
    ReportNotFoundError,
    export_report_json,
    export_report_pdf,
    get_report,
    list_reports,
)

router = APIRouter(prefix="/api", tags=["reports"])


@router.get("/reports")
def list_all_reports(limit: int = 50, offset: int = 0):
    """List stored report snapshots (newest first) with pagination."""
    try:
        return list_reports(limit=limit, offset=offset)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.get("/reports/{scan_id}")
def get_scan_report(scan_id: int):
    """Retrieve the stored JSON report for a scan."""
    try:
        report = get_report(scan_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No report has been generated for scan {}.".format(scan_id),
        )
    return report


@router.get("/reports/{scan_id}/export")
def export_scan_report(scan_id: int, format: str = "json"):
    """Download a stored report as a JSON or PDF file attachment."""
    output_format = (format or "json").strip().lower()
    if output_format not in ("json", "pdf"):
        raise HTTPException(
            status_code=400,
            detail="Unsupported export format '{}'. Use format=json or format=pdf.".format(
                format
            ),
        )

    if output_format == "json":
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".json", delete=False
            ) as temporary:
                temporary_path = temporary.name
            export_report_json(scan_id, temporary_path)
        except ReportNotFoundError:
            _silent_remove(temporary_path)
            raise HTTPException(
                status_code=404,
                detail="No report has been generated for scan {}.".format(scan_id),
            )
        return FileResponse(
            temporary_path,
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="hashguard_report_scan_{}.json"'.format(scan_id)
            },
            background=BackgroundTask(_silent_remove, temporary_path),
        )

    try:
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as temporary:
            temporary_path = temporary.name
        export_report_pdf(scan_id, temporary_path)
    except ReportNotFoundError:
        _silent_remove(temporary_path)
        raise HTTPException(
            status_code=404,
            detail="No report has been generated for scan {}.".format(scan_id),
        )
    except RuntimeError as error:
        _silent_remove(temporary_path)
        raise HTTPException(status_code=400, detail=str(error))

    return FileResponse(
        temporary_path,
        media_type="application/pdf",
        headers={
            "Content-Disposition": 'attachment; filename="hashguard_report_scan_{}.pdf"'.format(scan_id)
        },
        background=BackgroundTask(_silent_remove, temporary_path),
    )


def _silent_remove(path):
    try:
        os.remove(path)
    except OSError:
        pass
