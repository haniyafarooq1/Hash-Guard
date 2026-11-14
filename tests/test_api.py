"""API integration tests for the FastAPI backend (TRD section 8).

Verifies that every endpoint works end-to-end through the real
HTTP layer (FastAPI TestClient), using a temporary database, a temporary
monitored directory and a temporary baseline secret key.
"""

import os
import tempfile
import unittest
from pathlib import Path

import baseline_security
from fastapi.testclient import TestClient

from backend.api import path_rules
from backend.main import app
from backend.storage import database
from tests.test_helpers import HashGuardTestCase


class ApiTestCase(HashGuardTestCase):

    def setUp(self):
        super().setUp()
        self.original_key_file = baseline_security.KEY_FILE
        baseline_security.KEY_FILE = self.root / "secret.key"

        self.monitored = self.root / "Important_Files"
        self.monitored.mkdir()
        self.baseline_file = self.root / "baseline.json"
        (self.monitored / "notes.txt").write_text("Original document")

        self.client = TestClient(app)

    def tearDown(self):
        baseline_security.KEY_FILE = self.original_key_file
        super().tearDown()

    def create_baseline(self):
        response = self.client.post(
            "/api/baseline/create",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.baseline_file),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["success"])
        return response

    def run_scan(self):
        return self.client.post(
            "/api/scan",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.baseline_file),
            },
        )


class TestScanOrchestrator(ApiTestCase):

    def test_scan_endpoint_runs_full_flow(self):
        self.create_baseline()
        response = self.run_scan()
        self.assertEqual(response.status_code, 200)

        body = response.json()
        self.assertEqual(body["integrity_status"], "success")
        self.assertEqual(body["overall_status"], "clean")
        self.assertEqual(body["alerts_generated"], 0)
        self.assertIsNotNone(body["report_id"])

    def test_scan_endpoint_validates_directory(self):
        response = self.client.post("/api/scan", json={"directory": "  "})
        self.assertEqual(response.status_code, 400)


class TestLogEndpoints(ApiTestCase):

    def test_logs_and_scans_endpoints(self):
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")
        (self.monitored / "extra.js").write_text("alert(1)")
        self.run_scan()
        # The baseline is never auto-updated, so the second scan
        # re-detects the same changes (TRD rule: no automatic updates).
        self.run_scan()

        # Scan history
        history = self.client.get("/api/scans")
        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.json()["total"], 2)

        # Pagination + validation
        page = self.client.get("/api/scans", params={"limit": 1, "offset": 1})
        self.assertEqual(page.json()["total"], 2)
        self.assertEqual(len(page.json()["items"]), 1)
        bad = self.client.get("/api/scans", params={"limit": 0})
        self.assertEqual(bad.status_code, 400)

        # Scan detail
        detail = self.client.get("/api/scans/1")
        self.assertEqual(detail.status_code, 200)
        body = detail.json()
        self.assertEqual(body["scan"]["scan_id"], 1)
        self.assertEqual(len(body["events"]), 4)
        self.assertEqual(len(body["alerts"]), 3)
        self.assertTrue(body["report_available"])
        self.assertEqual(
            self.client.get("/api/scans/999").status_code, 404
        )

        # Activity logs with filters
        logs = self.client.get("/api/logs")
        self.assertEqual(logs.json()["total"], 8)  # 4 events per scan

        modified = self.client.get(
            "/api/logs", params={"event_type": "file_modified"}
        )
        self.assertEqual(modified.json()["total"], 2)
        self.assertEqual(
            modified.json()["items"][0]["file_path"], "notes.txt"
        )

        suspicious = self.client.get(
            "/api/logs", params={"event_type": "suspicious_file"}
        )
        self.assertEqual(suspicious.json()["total"], 2)

        by_scan = self.client.get("/api/logs", params={"scan_id": 2})
        self.assertEqual(by_scan.json()["total"], 4)
        self.assertTrue(
            all(item["scan_id"] == 2 for item in by_scan.json()["items"])
        )

        by_severity = self.client.get(
            "/api/logs", params={"severity": "high"}
        )
        self.assertEqual(by_severity.json()["total"], 2)  # 1 per scan

        invalid_date = self.client.get(
            "/api/logs", params={"start_date": "not-a-date"}
        )
        self.assertEqual(invalid_date.status_code, 400)

        # Individual event
        event_id = logs.json()["items"][0]["event_id"]
        event = self.client.get("/api/logs/{}".format(event_id))
        self.assertEqual(event.status_code, 200)
        self.assertEqual(event.json()["event_id"], event_id)
        self.assertEqual(self.client.get("/api/logs/99999").status_code, 404)


class TestAlertEndpoints(ApiTestCase):

    def test_alert_flow(self):
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")
        self.run_scan()

        listing = self.client.get("/api/alerts")
        self.assertEqual(listing.status_code, 200)
        body = listing.json()
        self.assertEqual(body["total"], 1)
        alert_id = body["items"][0]["alert_id"]

        # Filtering
        high = self.client.get("/api/alerts", params={"severity": "high"})
        self.assertEqual(high.json()["total"], 1)
        medium = self.client.get("/api/alerts", params={"severity": "medium"})
        self.assertEqual(medium.json()["total"], 0)
        integrity = self.client.get(
            "/api/alerts", params={"category": "integrity"}
        )
        self.assertEqual(integrity.json()["total"], 1)
        dismissed = self.client.get("/api/alerts", params={"status": "dismissed"})
        self.assertEqual(dismissed.json()["total"], 0)

        # Individual alert
        alert = self.client.get("/api/alerts/{}".format(alert_id))
        self.assertEqual(alert.status_code, 200)
        self.assertEqual(alert.json()["alert_id"], alert_id)
        self.assertEqual(
            self.client.get("/api/alerts/99999").status_code, 404
        )

        # Status update
        updated = self.client.patch(
            "/api/alerts/{}/status".format(alert_id), json={"status": "read"}
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.json()["status"], "read")

        dismissed_update = self.client.patch(
            "/api/alerts/{}/status".format(alert_id),
            json={"status": "dismissed"},
        )
        self.assertEqual(dismissed_update.json()["status"], "dismissed")

        # Invalid status value is rejected
        invalid = self.client.patch(
            "/api/alerts/{}/status".format(alert_id),
            json={"status": "deleted"},
        )
        self.assertEqual(invalid.status_code, 400)

        # Missing alert
        missing = self.client.patch(
            "/api/alerts/99999/status", json={"status": "read"}
        )
        self.assertEqual(missing.status_code, 404)

        # Summary reflects the change
        summary = self.client.get("/api/alerts/summary")
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json()["total"], 1)
        self.assertEqual(summary.json()["by_status"]["dismissed"], 1)


class TestReportEndpoints(ApiTestCase):

    def test_report_endpoints(self):
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")
        scan_response = self.run_scan()
        scan_id = scan_response.json()["scan_id"]

        # Retrieve JSON report
        report = self.client.get("/api/reports/{}".format(scan_id))
        self.assertEqual(report.status_code, 200)
        body = report.json()
        self.assertEqual(body["scan_id"], scan_id)
        self.assertEqual(
            body["overall_assessment"]["status"], "findings_detected"
        )
        self.assertEqual(len(body["alerts"]), 1)

        # Reports listing
        listing = self.client.get("/api/reports")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["total"], 1)
        self.assertEqual(listing.json()["items"][0]["scan_id"], scan_id)

        # JSON export
        exported = self.client.get(
            "/api/reports/{}/export".format(scan_id)
        )
        self.assertEqual(exported.status_code, 200)
        self.assertIn("application/json", exported.headers["content-type"])
        self.assertIn("attachment", exported.headers["content-disposition"])

        # PDF export
        pdf = self.client.get(
            "/api/reports/{}/export".format(scan_id),
            params={"format": "pdf"},
        )
        self.assertEqual(pdf.status_code, 200)
        self.assertIn("application/pdf", pdf.headers["content-type"])
        self.assertTrue(pdf.content.startswith(b"%PDF"))

        # Unsupported format and missing report
        self.assertEqual(
            self.client.get(
                "/api/reports/{}/export".format(scan_id),
                params={"format": "docx"},
            ).status_code,
            400,
        )
        self.assertEqual(
            self.client.get("/api/reports/999").status_code, 404
        )
        self.assertEqual(
            self.client.get("/api/reports/999/export").status_code, 404
        )


class TestHealth(ApiTestCase):

    def test_root_and_health(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()["status"], "ok")


class TestPathValidation(ApiTestCase):
    """The API must not become an arbitrary filesystem scanner.

    Directories and baseline files are restricted to the configured
    allowed roots, baseline files must be .json, scans require an
    existing baseline, and overwriting a baseline is opt-in only.
    """

    def setUp(self):
        super().setUp()
        # Restrict the API to this test's temporary root only, so the
        # outside-roots cases below are deterministic.
        path_rules.set_allowed_roots([self.root])

    def tearDown(self):
        path_rules.reset_allowed_roots()
        super().tearDown()

    def test_scan_directory_outside_allowed_roots_is_forbidden(self):
        with tempfile.TemporaryDirectory() as outside:
            response = self.client.post(
                "/api/scan",
                json={
                    "directory": outside,
                    "baseline_file": str(self.baseline_file),
                },
            )
            self.assertEqual(response.status_code, 403)
            self.assertIn("outside the allowed roots",
                          response.json()["detail"])

    def test_scan_nonexistent_directory_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={
                "directory": str(self.root / "does_not_exist"),
                "baseline_file": str(self.baseline_file),
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_scan_file_as_directory_is_rejected(self):
        target = self.root / "plain.txt"
        target.write_text("a file, not a directory")
        response = self.client.post(
            "/api/scan",
            json={
                "directory": str(target),
                "baseline_file": str(self.baseline_file),
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_scan_with_missing_baseline_is_rejected(self):
        response = self.client.post(
            "/api/scan",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.root / "absent_baseline.json"),
            },
        )
        self.assertEqual(response.status_code, 404)
        self.assertIn("Baseline file not found", response.json()["detail"])

    def test_scan_with_non_json_baseline_is_rejected(self):
        bogus = self.root / "baseline.txt"
        bogus.write_text("not a baseline")
        response = self.client.post(
            "/api/scan",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(bogus),
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_scan_baseline_outside_allowed_roots_is_forbidden(self):
        with tempfile.TemporaryDirectory() as outside:
            baseline = Path(outside) / "baseline.json"
            baseline.write_text("{}")
            response = self.client.post(
                "/api/scan",
                json={
                    "directory": str(self.monitored),
                    "baseline_file": str(baseline),
                },
            )
            self.assertEqual(response.status_code, 403)

    def test_baseline_creation_outside_allowed_roots_is_forbidden(self):
        with tempfile.TemporaryDirectory() as outside:
            response = self.client.post(
                "/api/baseline/create",
                json={
                    "directory": str(self.monitored),
                    "baseline_file": str(Path(outside) / "baseline.json"),
                },
            )
            self.assertEqual(response.status_code, 403)

    def test_baseline_creation_requires_explicit_overwrite(self):
        # first creation succeeds
        first = self.client.post(
            "/api/baseline/create",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.baseline_file),
            },
        )
        self.assertEqual(first.status_code, 200)

        # second creation without the overwrite flag -> 409, the
        # existing baseline stays untouched
        conflict = self.client.post(
            "/api/baseline/create",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.baseline_file),
            },
        )
        self.assertEqual(conflict.status_code, 409)
        self.assertIn("overwrite", conflict.json()["detail"])

        # explicit overwrite succeeds
        replaced = self.client.post(
            "/api/baseline/create",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.baseline_file),
                "overwrite": True,
            },
        )
        self.assertEqual(replaced.status_code, 200)
        self.assertTrue(replaced.json()["success"])

    def test_baseline_creation_for_non_json_target_is_rejected(self):
        response = self.client.post(
            "/api/baseline/create",
            json={
                "directory": str(self.monitored),
                "baseline_file": str(self.root / "baseline.sqlite"),
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_symlink_escaping_allowed_roots_is_rejected(self):
        try:
            with tempfile.TemporaryDirectory() as outside:
                link = self.root / "escape_link"
                os.symlink(outside, link)
                try:
                    response = self.client.post(
                        "/api/scan",
                        json={
                            "directory": str(link),
                            "baseline_file": str(self.baseline_file),
                        },
                    )
                    self.assertEqual(response.status_code, 403)
                finally:
                    link.unlink()
        except (OSError, NotImplementedError):
            self.skipTest("symlinks are not available on this platform")

    def test_valid_paths_inside_allowed_roots_still_work(self):
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")
        response = self.run_scan()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["overall_status"],
                         "findings_detected")


if __name__ == "__main__":
    unittest.main()
