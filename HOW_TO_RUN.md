# Hash Guard — How to Run & Verify

Hash Guard is a File Integrity Monitoring System:

| Layer | Responsibility | Key files |
|-------|----------------|-----------|
| Baseline & hashing (SHA-256 + HMAC signing) | `baseline.py`, `baseline_security.py` |
| Integrity checking & suspicious-file detection | `integrity_checker.py`, `suspicious_detector.py` |
| Activity logs, security alerts, reports | `activity_logger.py`, `alerts.py`, `report_generator.py` |
| REST API + scan orchestrator | `backend/` |
| Web UI | `frontend/` |

Everything is integrated: one scan flows through
`check_integrity()` → `check_suspicious_files()` → `log_scan()` →
`generate_alerts()` → `generate_report()` and is visible in the UI.

---

## 0. Prerequisites

- **Python 3.10+** (developed on 3.12)
- **Node.js 18+** and npm (only needed for the web UI)

```bash
# 1) Enter the project
cd Hash-Guard-main

# 2) Install Python dependencies
pip install -r requirements.txt
# fastapi, uvicorn, reportlab, httpx
```

---

## 1. Run the automated tests (fastest way to verify everything works)

```bash
# From the project root — runs ALL tests:
python3 -m pytest tests/ -v
```

Expected result: **104 passed** (takes ~2 seconds).

Test files and what they cover:

| Test file | Covers |
|-----------|--------|
| `tests/test_baseline.py` | Baseline create/load/update, HMAC signature |
| `tests/test_integrity_checker.py` | Modified/added/deleted/renamed detection, tamper-proof baseline |
| `tests/test_suspicious_detector.py` | `.exe`/`.bat`/`.ps1` flagging, executable permissions |
| `tests/test_activity_logger.py` | Scan history, per-scan events, activity-log filters |
| `tests/test_alerts.py` | Alert generation, severity, status workflow |
| `tests/test_report_generator.py` | Report snapshot, JSON & PDF export |
| `tests/test_pipeline_integration.py` | Full pipeline + failure conditions + persistence across restart |
| `tests/test_api.py` | FastAPI endpoints end-to-end |
| `tests/test_storage.py` | SQLite connection lifecycle (per-thread isolation) |

To run one area only:

```bash
python3 -m pytest tests/test_baseline.py tests/test_integrity_checker.py tests/test_suspicious_detector.py -v   # detection units
python3 -m pytest tests/test_activity_logger.py tests/test_alerts.py tests/test_report_generator.py -v          # logging/alerts/reports units
python3 -m pytest tests/test_pipeline_integration.py -v                                                          # integration
python3 -m pytest tests/test_api.py tests/test_storage.py -v                                                    # API + storage
```

---

## 2. Run the CLI (baseline management menu)

```bash
python3 main.py
```

Menu options: `1` create baseline, `2` view baseline, `3` update baseline, `4` exit.
It asks for a folder path, e.g. `/path/to/my/project`.

The signed baseline is stored as `baseline.json` + `baseline.json.sig`
(HMAC-SHA256, key in `~/.hash_guard/secret.key`).

---

## 3. Run the FastAPI backend

```bash
# From the project root
python3 -m uvicorn backend.main:app --reload --port 8000
```

- The SQLite database is created automatically at `~/.hash_guard/hashguard.db`.
- Interactive API documentation (Swagger UI): **http://localhost:8000/docs**

### 3a. Try a complete scan from the command line

```bash
# 1) Create a demo folder with two files
mkdir -p /tmp/demo && echo "print('v1')" > /tmp/demo/app.py && echo "debug=false" > /tmp/demo/config.txt

# 2) Create + sign the baseline for it
curl -X POST http://localhost:8000/api/baseline/create \
     -H "Content-Type: application/json" \
     -d '{"directory": "/tmp/demo", "baseline_file": "/tmp/demo_baseline.json"}'

# 3) Tamper with the folder (modify a file, drop in a fake malware.exe, delete one)
echo "print('tampered')" >> /tmp/demo/app.py
echo "MZ" > /tmp/demo/malware.exe
rm /tmp/demo/config.txt

# 4) Run a full orchestrated scan — this logs events, generates alerts
#    and builds a report in one call:
curl -X POST http://localhost:8000/api/scan \
     -H "Content-Type: application/json" \
     -d '{"directory": "/tmp/demo", "baseline_file": "/tmp/demo_baseline.json"}'
```

Expected response (abridged):

```json
{
  "scan_id": 1,
  "overall_status": "findings_detected",
  "integrity_summary": { "modified": 1, "added": 0, "deleted": 1, ... },
  "suspicious_summary": { "suspicious_files": 1, "executable_files": 1, ... },
  "alerts_generated": 2,
  "report_id": 1
}
```

### 3b. API endpoint cheat-sheet

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET  | `/api/health` | Liveness check |
| POST | `/api/baseline/create` | Create + HMAC-sign a baseline |
| POST | `/api/scan` | Full orchestrated scan |
| GET  | `/api/scans?limit=50` | Scan history |
| GET  | `/api/scans/{scan_id}` | One scan with its events + alerts |
| GET  | `/api/logs?limit=&offset=&event_type=&severity=` | Activity log (every file event) |
| GET  | `/api/logs/{event_id}` | Single log entry |
| GET  | `/api/alerts?severity=&status=&scan_id=` | Security alerts |
| GET  | `/api/alerts/summary` | Counts by severity / status |
| PATCH| `/api/alerts/{alert_id}/status` | Update status: `unread` / `read` / `dismissed` |
| GET  | `/api/reports?limit=` | Report list |
| GET  | `/api/reports/{scan_id}` | Full report for a scan |
| GET  | `/api/reports/{scan_id}/export?format=json` | Download report as JSON |
| GET  | `/api/reports/{scan_id}/export?format=pdf` | Download report as PDF |

Examples:

```bash
curl http://localhost:8000/api/scans
curl http://localhost:8000/api/logs?severity=high
curl http://localhost:8000/api/alerts/summary
curl -X PATCH http://localhost:8000/api/alerts/1/status \
     -H "Content-Type: application/json" -d '{"status": "read"}'
curl "http://localhost:8000/api/reports/1/export?format=pdf" -o report.pdf
```

### 3c. Scan status meanings

| Status | Meaning |
|--------|---------|
| `clean` | Both the integrity check and the suspicious-file detection ran successfully: no changes, no suspicious files, no errors |
| `findings_detected` | Changes or suspicious files were found (both stages completed) |
| `completed_with_errors` | Both stages completed, but per-file errors were reported |
| `baseline_unavailable` | The baseline could not be loaded or authenticated (critical alert) |
| `invalid_directory` | The monitored directory is invalid or unavailable |

---

## 4. Run the web UI

Open a **second terminal** (keep the API running on port 8000):

```bash
cd frontend
npm install        # first time only
npm run dev
```

Then open **http://localhost:5173**.

The Vite dev server proxies `/api/*` to `http://localhost:8000`, so no
CORS or URL configuration is needed. (Optional: set `VITE_API_BASE`
in `frontend/.env` to point somewhere else.)

### Pages to check

| Page (route) | What you should see |
|--------------|---------------------|
| **Dashboard** (`/`) | Latest scan status, alert counters, baseline creation and "run scan" forms |
| **Activity Logs** (`/logs`) | Every file event of every scan (modified / added / deleted / renamed / suspicious / scan errors), filterable by type, severity and date; click a scan to see its timeline |
| **Alerts** (`/alerts`) | Alert cards with severity badges; mark as read / dismissed; summary counters |
| **Reports** (`/reports`) | One report per scan; open a report for full details; download JSON / PDF |

### Recommended 2-minute verification walkthrough

1. Start the backend (step 3) and the frontend (step 4).
2. Run the four `curl` commands from §3a (create baseline → tamper → scan).
3. Dashboard → you should see a scan with status **findings_detected**.
4. Alerts page → 2 alerts ("File Modified" for `app.py`, "Suspicious File Detected" for `malware.exe`), both **high** severity.
5. Mark one alert as dismissed → it disappears from the unread counter.
6. Activity Logs page → events for the modified, deleted and suspicious files, tagged by source (`integrity_checker`, `suspicious_detector`).
7. Reports page → open the report of the scan; click **PDF** and **JSON** to download the exports.
8. Run the scan **again without changing anything** → the same findings
   are re-detected (the baseline is never auto-updated), and the history
   now shows 2 scans. This proves persistence in SQLite across scans.

---

## 5. Where data lives

| Path | Content |
|------|---------|
| `~/.hash_guard/secret.key` | HMAC key that protects the baseline against tampering |
| `~/.hash_guard/hashguard.db` | SQLite database: scans, events, alerts, reports |
| `baseline.json` / `baseline.json.sig` | Signed baseline (created where you point the tool) |
| `exports/` (or the path you pass) | JSON / PDF report exports |

To start with a clean database: `rm ~/.hash_guard/hashguard.db`
(the schema is recreated on the next server start).

---

## 6. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError: baseline` when running tests | Run `pytest` from the project root, not from inside `tests/` |
| `uvicorn: command not found` | Use `python3 -m uvicorn ...` |
| Frontend shows "Failed to fetch" | Backend is not running — start uvicorn on port 8000 first |
| Port 8000 already in use | `uvicorn backend.main:app --port 8001` (the Vite proxy targets 8000 by default; change it in `frontend/vite.config.js` if needed) |
| `npm run dev` fails after pulling | Delete `frontend/node_modules` and run `npm install` again |
| Alerts from old experiments keep showing | Delete `~/.hash_guard/hashguard.db` and restart the API |
