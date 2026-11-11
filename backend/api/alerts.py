"""Security alert endpoints (TRD section 8.1).

GET   /api/alerts                    – retrieve alerts with filters
GET   /api/alerts/summary            – aggregate counts (dashboard badge)
GET   /api/alerts/{alert_id}         – retrieve one alert
PATCH /api/alerts/{alert_id}/status  – update alert status
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from alerts import (
    get_alert_by_id,
    get_alert_summary,
    get_alerts,
    update_alert_status,
)

router = APIRouter(prefix="/api", tags=["security-alerts"])


class AlertStatusUpdate(BaseModel):
    status: str


@router.get("/alerts")
def list_alerts(
    severity: str = None,
    category: str = None,
    status: str = None,
    scan_id: int = None,
    start_date: str = None,
    end_date: str = None,
    limit: int = 50,
    offset: int = 0,
):
    """Retrieve alerts filtered by severity, category, status, scan or date."""
    try:
        return get_alerts(
            severity=severity,
            category=category,
            status=status,
            scan_id=scan_id,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


# Registered BEFORE /alerts/{alert_id} so "summary" is not treated as an id.
@router.get("/alerts/summary")
def alerts_summary():
    """Return aggregate alert counts (total, unread, per severity/status)."""
    return get_alert_summary()


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    """Retrieve an individual alert."""
    try:
        alert = get_alert_by_id(alert_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    if alert is None:
        raise HTTPException(
            status_code=404, detail="Alert {} not found.".format(alert_id)
        )
    return alert


@router.patch("/alerts/{alert_id}/status")
def patch_alert_status(alert_id: int, update: AlertStatusUpdate):
    """Update an alert status to 'unread', 'read' or 'dismissed'.

    Example request body: {"status": "read"}
    """
    try:
        alert = update_alert_status(alert_id, update.status)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    if alert is None:
        raise HTTPException(
            status_code=404,
            detail="Alert {} not found.".format(alert_id),
        )
    return alert
