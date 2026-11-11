"""Scan orchestration endpoints (TRD section 8.1).

POST /api/scan             – run one complete scan (orchestrated)
POST /api/baseline/create  – create and sign a baseline

The scan endpoint belongs to the backend scan orchestrator: it calls
``check_integrity()`` and ``check_suspicious_files()``, then hands both
results to the logging, alert and reporting functions. It contains no
logging, alert or reporting logic of its own.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.services import scan_service

router = APIRouter(prefix="/api", tags=["scan-orchestrator"])


class ScanRequest(BaseModel):
    directory: str
    baseline_file: str = "baseline.json"


class BaselineRequest(BaseModel):
    directory: str
    baseline_file: str = "baseline.json"


@router.post("/scan")
def run_scan(request: ScanRequest):
    """Run a complete scan: integrity check, suspicious detection,
    logging, alert generation and report generation."""
    try:
        return scan_service.run_scan(request.directory, request.baseline_file)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.post("/baseline/create")
def create_baseline(request: BaselineRequest):
    """Create and sign a baseline for a monitored directory."""
    try:
        return scan_service.create_monitored_baseline(
            request.directory, request.baseline_file
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
