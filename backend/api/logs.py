"""Activity log and scan history endpoints (TRD section 8.1).

GET  /api/logs             – retrieve activity logs (filter + paginate)
GET  /api/logs/{event_id}  – retrieve an individual event
GET  /api/scans            – retrieve scan history
GET  /api/scans/{scan_id}  – retrieve one scan and its details
"""

from fastapi import APIRouter, HTTPException

from activity_logger import (
    get_activity_logs,
    get_event_by_id,
    get_scan_by_id,
    get_scan_events,
    get_scan_history,
)
from alerts import get_alerts
from report_generator import get_report

router = APIRouter(prefix="/api", tags=["activity-logs"])


@router.get("/logs")
def list_activity_logs(
    event_type: str = None,
    severity: str = None,
    start_date: str = None,
    end_date: str = None,
    scan_id: int = None,
    limit: int = 100,
    offset: int = 0,
):
    """Retrieve activity logs with optional filtering and pagination."""
    try:
        return get_activity_logs(
            event_type=event_type,
            severity=severity,
            start_date=start_date,
            end_date=end_date,
            scan_id=scan_id,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.get("/logs/{event_id}")
def get_event(event_id: int):
    """Retrieve an individual activity event."""
    try:
        event = get_event_by_id(event_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    if event is None:
        raise HTTPException(
            status_code=404, detail="Activity event {} not found.".format(event_id)
        )
    return event


@router.get("/scans")
def list_scans(limit: int = 50, offset: int = 0):
    """Retrieve the scan history (newest first) with pagination."""
    try:
        return get_scan_history(limit=limit, offset=offset)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    """Retrieve one scan together with its events, alerts and report state."""
    try:
        scan = get_scan_by_id(scan_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    if scan is None:
        raise HTTPException(
            status_code=404, detail="Scan {} not found.".format(scan_id)
        )

    alerts = get_alerts(scan_id=scan_id, limit=500, offset=0)
    return {
        "scan": scan,
        "events": get_scan_events(scan_id),
        "alerts": alerts["items"],
        "report_available": get_report(scan_id) is not None,
    }
