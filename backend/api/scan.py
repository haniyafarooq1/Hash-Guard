"""Scan orchestration endpoints (TRD section 8.1).

POST /api/scan             – run one complete scan (orchestrated)
POST /api/baseline/create  – create and sign a baseline

Every requested path is validated against the API path rules
(backend/api/path_rules.py) BEFORE it reaches the scan service: the API
only scans directories inside the configured allowed roots, and baseline
files can only be created or overwritten inside those roots (replacing
an existing baseline requires ``"overwrite": true``).

The scan endpoint belongs to the backend scan orchestrator: it calls
``check_integrity()`` and ``check_suspicious_files()``, then hands both
results to the logging, alert and reporting functions. It contains no
logging, alert or reporting logic of its own.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.api import path_rules
from backend.api.path_rules import PathRuleError
from backend.services import scan_service

router = APIRouter(prefix="/api", tags=["scan-orchestrator"])


class ScanRequest(BaseModel):
    directory: str
    baseline_file: str = "baseline.json"


class BaselineRequest(BaseModel):
    directory: str
    baseline_file: str = "baseline.json"
    overwrite: bool = False


@router.post("/scan")
def run_scan(request: ScanRequest):
    """Run a complete scan: integrity check, suspicious detection,
    logging, alert generation and report generation."""
    try:
        directory = path_rules.resolve_monitored_directory(request.directory)
        baseline = path_rules.resolve_baseline_file(
            request.baseline_file, must_exist=True
        )
    except PathRuleError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error))
    try:
        return scan_service.run_scan(str(directory), str(baseline))
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@router.post("/baseline/create")
def create_baseline(request: BaselineRequest):
    """Create and sign a baseline for a monitored directory.

    Refuses to overwrite an existing baseline file unless the request
    explicitly passes ``"overwrite": true``.
    """
    try:
        directory = path_rules.resolve_monitored_directory(request.directory)
        baseline = path_rules.resolve_baseline_file(
            request.baseline_file,
            must_exist=False,
            for_write=True,
            overwrite=request.overwrite,
        )
    except PathRuleError as error:
        raise HTTPException(status_code=error.status_code, detail=str(error))
    try:
        return scan_service.create_monitored_baseline(
            str(directory), str(baseline)
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
