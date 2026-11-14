# Hash Guard – File Integrity Monitoring System

**Course:** CS3002 – Information Security · **Semester:** Fall 2026

Hash Guard monitors a folder for file integrity changes (modified,
added, deleted, renamed files) and suspicious files (risky extensions,
executables, newly added files), using an HMAC-SHA256 signed baseline so
tampered baselines are rejected. Every scan attempt is recorded with its
full activity log, security alerts and a report snapshot.

```
                    React Frontend (Vite + Tailwind)
                          |
                       HTTP/JSON
                          |
                     FastAPI Backend
                          |
                    Scan Orchestrator
                          |
             +------------+------------+
             |                         |
       Integrity Checker        Suspicious Detector
             |                         |
             +------------+------------+
                          |
                     Scan Results
                          |
              +-----------+-----------+
              |           |           |
          Activity      Alerts      Reports
           Logger       Module       Module
              |           |           |
              +-----------+-----------+
                          |
                       SQLite
```

## Modules

| Module | Responsibility |
|---|---|
| `baseline.py` | SHA-256 hashing, baseline create / load / update |
| `baseline_security.py` | HMAC-SHA256 baseline signing + verification |
| `integrity_checker.py` | Detect modified / added / deleted / renamed files |
| `suspicious_detector.py` | Detect risky extensions, executables, new files |
| `activity_logger.py` | Record scans + activity events (FR-01..FR-07) |
| `alerts.py` | Generate + manage security alerts (FR-08..FR-16) |
| `report_generator.py` | JSON / PDF scan reports (FR-17..FR-22) |
| `backend/` | FastAPI API, scan orchestrator, SQLite storage |
| `frontend/` | Dashboard, Activity Logs, Alerts, Reports pages |

The logging, alert and reporting layer is a pure consumer: it uses the
result dictionaries of `check_integrity()` and
`check_suspicious_files()`, never recalculates hashes, never verifies or
updates the baseline, and never repeats detection logic.

## Quick start

### 1. Backend (Python 3.10+)

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```

Interactive API docs: <http://localhost:8000/docs>

### 2. Frontend (Node 18+)

```bash
cd frontend
npm install
npm run dev
```

Open <http://localhost:5173> (the Vite dev server proxies `/api` to
port 8000).

### 3. CLI (baseline management menu)

```bash
python main.py
```

### 4. Try it end to end

1. On the **Dashboard**, create a baseline for a folder (e.g. an
   `Important_Files` directory). Re-creating an existing baseline
   requires ticking "Replace existing baseline file".
2. Click **Run scan** – a clean scan is recorded, no alerts.
3. Change / add / delete / rename files in the folder (try adding an
   `unexpected.exe`), then **Run scan** again.
4. Review the results in **Activity Logs**, **Alerts** (mark read /
   dismiss) and **Reports** (open the report, download JSON / PDF).

## Running the tests

```bash
python -m pytest tests/ -v          # or: python -m unittest discover -v
```

| File | Coverage |
|---|---|
| `tests/test_baseline.py` | Baseline create/load/update, HMAC signature |
| `tests/test_integrity_checker.py` | Modified/added/deleted/renamed detection, tamper-proof baseline |
| `tests/test_suspicious_detector.py` | Risky extensions, executable permissions |
| `tests/test_activity_logger.py` | TRD 11.1 scenarios + assessments, incomplete scans, event appending |
| `tests/test_alerts.py` | TRD 11.2 scenarios + dedupe, filtering, severity config, pinned baseline severity |
| `tests/test_report_generator.py` | TRD 11.3 scenarios + snapshots, JSON/PDF export |
| `tests/test_scan_service.py` | Orchestrator stage isolation (alert/report/detector failures) |
| `tests/test_pipeline_integration.py` | TRD 11.4 scenarios 1–12 (real detection modules, full pipeline) |
| `tests/test_api.py` | FastAPI endpoints end-to-end incl. path validation |
| `tests/test_storage.py` | SQLite connection lifecycle (per-thread isolation, cross-thread cleanup) |

All tests use temporary directories and temporary databases; the
baseline secret key is redirected to a temporary file so the real key is
never touched.

## REST API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/logs` | Activity logs (filters: `event_type`, `severity`, `start_date`, `end_date`, `scan_id`, `limit`, `offset`) |
| GET | `/api/logs/{event_id}` | One activity event |
| GET | `/api/scans` | Scan history (paginated) |
| GET | `/api/scans/{scan_id}` | One scan + its events, alerts, report state |
| GET | `/api/alerts` | Alerts (filters: `severity`, `category`, `status`, `scan_id`, `start_date`, `end_date`, `limit`, `offset`) |
| GET | `/api/alerts/summary` | Aggregate counts (total, unread, per severity/status) |
| GET | `/api/alerts/{alert_id}` | One alert |
| PATCH | `/api/alerts/{alert_id}/status` | Update status: `{"status": "read"}` (`unread` / `read` / `dismissed`) |
| GET | `/api/reports` | Stored report snapshots (paginated) |
| GET | `/api/reports/{scan_id}` | JSON report of a scan |
| GET | `/api/reports/{scan_id}/export?format=json\|pdf` | Download a report |
| POST | `/api/scan` | Run a full scan: `{"directory": "...", "baseline_file": "baseline.json"}` |
| POST | `/api/baseline/create` | Create + sign a baseline; replacing an existing file requires `"overwrite": true` |

## API path restrictions

The API is not an arbitrary filesystem scanner. Before any request
reaches the detection modules:

* the monitored directory must exist and lie inside the configured
  **allowed roots** (symlinks are resolved, so a link cannot escape);
* the baseline file must be a `.json` file inside the allowed roots;
* scan requests require an existing baseline;
* baseline creation refuses to overwrite an existing file unless the
  request explicitly passes `"overwrite": true`.

Allowed roots come from the `HASHGUARD_ALLOWED_ROOTS` environment
variable (paths separated by `:` on POSIX / `;` on Windows). By default
they are the process working directory and the system temporary
directory.

## Database

SQLite, stored **outside the monitored directories** so Hash Guard never
detects its own database: `~/.hash_guard/hashguard.db` by default,
overridable with the `HASHGUARD_DB` environment variable or
`database.set_database_path()` (used by the tests). Parent directories
of a custom location are created automatically.

Tables: `scans` (one row per scan attempt), `activity_logs` (events),
`alerts` (with `UNIQUE (scan_id, dedupe_key)` for duplicate prevention),
`reports` (one snapshot per scan, refreshed in place). Foreign keys are
enforced on every connection; all queries are parameterized.

Connections are isolated per thread; every connection is additionally
tracked in a process-wide registry so `reset_connections()` can close
the connections held by worker threads during test teardown (required
on Windows, where an open handle keeps the file undeletable – WinError
32).

## Design decisions

* **No false clean results.** The overall assessment follows the FR-19
  priority `invalid_directory` → `baseline_unavailable` → `incomplete`
  → `completed_with_errors` → `findings_detected` → `clean`.
  `clean` is derived only when the integrity check AND the
  suspicious-file detection both ran and completed successfully with no
  findings and no errors. A missing, not-started, crashed or unknown
  stage yields `incomplete` – never a clean result. Original statuses
  are always preserved separately.
* **Stage isolation in the scan orchestrator.** A failure of the alert
  stage never prevents report generation (and vice versa); an unexpected
  crash of a detection stage is captured in a synthetic `failed` result
  so the attempt is still recorded, assessed as `incomplete`; every
  stage failure is appended to the scan's activity log. Only a failure
  of the recording stage itself propagates to the caller.
* **Alert deduplication.** Every alert has a stable `dedupe_key`
  (`modified:<path>`, `suspicious:<path>`, `baseline_unavailable`, …)
  and a `UNIQUE (scan_id, dedupe_key)` constraint, so re-generating
  alerts for a scan never duplicates records. The `suspicious_files`
  array is the only source of suspicious alerts – the overlapping
  `executable_files` / `newly_added_files` arrays are just
  cross-referenced.
* **Configurable severities, with a pinned floor.**
  `alerts.set_severity_config({...})` overrides the default severity
  mapping at runtime; nothing is hard-coded in the frontend. The
  severity of baseline verification / authentication failures is pinned
  to `critical` and cannot be lowered – changing it raises a
  `ValueError`, and the alert generation enforces the same floor as
  defense in depth.
* **Report snapshots.** Reports are frozen at generation time (changing
  an alert's status later never rewrites history) and re-generation
  replaces the snapshot in place (`ON CONFLICT(scan_id) DO UPDATE`).
  A report is generated for every recorded scan attempt, including
  failed and incomplete ones.
* **Failure isolation in storage.** Scan + events are written in one
  transaction; alert and report generation run in separate
  transactions, so a later failure never destroys earlier records, and
  database errors propagate clearly instead of being swallowed.

## Known limitation: empty baselines

`check_integrity()` currently treats an empty loaded baseline
(`if not baseline:`) as `baseline_unavailable`. The logging layer
preserves that status as-is and never guesses the baseline was valid.
Once the upstream status distinguishes a legitimately empty,
authenticated baseline from a loading / authentication failure, the
logging, alert and reporting layers need no changes.

## Project structure

```
Hash-Guard/
├── baseline.py                # baseline create/load/update
├── baseline_security.py       # HMAC-SHA256 signing/verification
├── integrity_checker.py       # integrity detection
├── suspicious_detector.py     # suspicious-file detection
├── main.py                    # CLI menu
│
├── activity_logger.py         # activity logging
├── alerts.py                  # security alerts
├── report_generator.py        # report snapshots + JSON/PDF export
│
├── backend/
│   ├── main.py                # FastAPI app
│   ├── api/                   # logs / alerts / reports / scan routers + path rules
│   ├── services/scan_service.py   # scan orchestrator (stage isolation)
│   └── storage/database.py    # SQLite schema + connection lifecycle
│
├── frontend/                  # Vite + React + Tailwind
│   └── src/
│       ├── pages/             # Dashboard, ActivityLogs, Alerts, Reports, ReportDetail
│       ├── api.js             # API client
│       └── components/ui.jsx
│
├── tests/                     # unit + integration + API + storage tests
└── requirements.txt
```
