"""Hash Guard FastAPI backend (backend/main.py).

Exposes the activity log, security alert and report functionality
through a REST API, together with the scan orchestrator. The API layer
contains no security logic of its own: every endpoint calls the tested
Python modules (integrity checker, suspicious detector, activity
logger, alerts, report generator).

Run from the project root:

    uvicorn backend.main:app --reload --port 8000
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import alerts, logs, reports, scan
from backend.storage import database


@asynccontextmanager
async def lifespan(application: FastAPI):
    # Make sure the SQLite schema exists before serving requests.
    database.init_db()
    yield


app = FastAPI(
    title="Hash Guard API",
    description=(
        "File Integrity Monitoring System - REST API for scan history, "
        "activity logs, security alerts and reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# The Vite dev server runs on http://localhost:5173.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(reports.router)
app.include_router(scan.router)


@app.get("/", tags=["health"])
def root():
    return {
        "service": "Hash Guard API",
        "version": "1.0.0",
        "database": str(database.get_database_path()),
        "docs": "/docs",
    }


@app.get("/api/health", tags=["health"])
def health():
    return {"status": "ok"}
