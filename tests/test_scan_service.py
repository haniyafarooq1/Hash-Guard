"""Tests for the scan orchestrator's stage isolation
(backend/services/scan_service.py, TRD section 8.3).

Verifies that a failure in one workflow stage never destroys the
results of the other stages, that unexpected failures are recorded in
the activity log, and that a scan whose detection stages did not both
complete is assessed as ``incomplete`` - never as a clean result.
"""

import sqlite3
import unittest
from unittest import mock

import baseline_security
from activity_logger import get_scan_by_id, get_scan_events
from alerts import get_alerts
from backend.services import scan_service
from backend.storage import database
from report_generator import get_report
from tests.test_helpers import HashGuardTestCase


class ScanServiceTestCase(HashGuardTestCase):
    """Base: temporary monitored folder + temporary baseline secret key."""

    def setUp(self):
        super().setUp()
        self.original_key_file = baseline_security.KEY_FILE
        baseline_security.KEY_FILE = self.root / "secret.key"

        self.monitored = self.root / "Important_Files"
        self.monitored.mkdir()
        self.baseline_file = self.root / "baseline.json"
        (self.monitored / "notes.txt").write_text("Original document")

    def tearDown(self):
        baseline_security.KEY_FILE = self.original_key_file
        super().tearDown()

    def create_baseline(self):
        from baseline import create_baseline
        self.assertTrue(
            create_baseline(str(self.monitored), str(self.baseline_file))
        )

    def run_scan(self):
        return scan_service.run_scan(
            str(self.monitored), str(self.baseline_file)
        )

    def stage_failure_events(self, scan_id):
        return [
            event for event in get_scan_events(scan_id)
            if event["event_type"] == "scan_error"
            and event["source"] == "system"
        ]


class TestStageIsolation(ScanServiceTestCase):

    def test_alert_failure_does_not_block_the_report(self):
        """A crash in the alert stage leaves scan, events AND report."""
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")

        with mock.patch.object(
            scan_service,
            "generate_alerts",
            side_effect=RuntimeError("alert engine exploded"),
        ):
            result = self.run_scan()

        # the scan itself was recorded normally
        self.assertEqual(result["integrity_status"], "success")
        self.assertEqual(result["overall_status"], "findings_detected")

        # the alert stage failed, but the report was still generated
        self.assertEqual(result["alerts_generated"], 0)
        self.assertIsNotNone(result["report_id"])
        self.assertIn(
            "alert_generation",
            [failure["stage"] for failure in result["stage_failures"]],
        )

        # the failure is visible in the activity log
        failures = self.stage_failure_events(result["scan_id"])
        self.assertTrue(
            any("alert_generation" in event["description"]
                for event in failures)
        )

        # and the report snapshot explains the missing alert list
        report = get_report(result["scan_id"])
        alert_titles = [alert["title"] for alert in report["alerts"]]
        self.assertIn("Alert Generation Failed", alert_titles)

        # no alerts were actually stored for the scan
        self.assertEqual(get_alerts(scan_id=result["scan_id"])["total"], 0)

    def test_report_failure_keeps_scan_and_alerts(self):
        """A crash in the report stage leaves the scan and its alerts."""
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")

        with mock.patch.object(
            scan_service,
            "generate_report",
            side_effect=RuntimeError("report engine exploded"),
        ):
            result = self.run_scan()

        self.assertIsNone(result["report_id"])
        self.assertIn(
            "report_generation",
            [failure["stage"] for failure in result["stage_failures"]],
        )

        # everything before the report stage is intact
        self.assertEqual(result["overall_status"], "findings_detected")
        self.assertEqual(result["alerts_generated"], 1)
        self.assertEqual(get_alerts(scan_id=result["scan_id"])["total"], 1)
        scan = get_scan_by_id(result["scan_id"])
        self.assertIsNotNone(scan)
        failures = self.stage_failure_events(result["scan_id"])
        self.assertTrue(
            any("report_generation" in event["description"]
                for event in failures)
        )

    def test_unexpected_integrity_crash_is_recorded_and_never_clean(self):
        """A crashing integrity check still produces a recorded scan,
        assessed as incomplete - never clean."""
        self.create_baseline()

        with mock.patch.object(
            scan_service,
            "check_integrity",
            side_effect=RuntimeError("checker crashed"),
        ):
            result = self.run_scan()

        self.assertEqual(result["integrity_status"], "failed")
        self.assertEqual(result["overall_status"], "incomplete")
        self.assertIn(
            "integrity_check",
            [failure["stage"] for failure in result["stage_failures"]],
        )

        # the scan is recorded with its events, including the crash
        scan = get_scan_by_id(result["scan_id"])
        self.assertEqual(scan["overall_status"], "incomplete")
        events = get_scan_events(result["scan_id"])
        types = [event["event_type"] for event in events]
        self.assertIn("scan_incomplete", types)
        self.assertIn("scan_error", types)
        self.assertTrue(
            any("integrity_check" in event["description"]
                for event in self.stage_failure_events(result["scan_id"]))
        )

        # the report is still generated for the failed attempt (FR-17)
        self.assertIsNotNone(result["report_id"])
        report = get_report(result["scan_id"])
        self.assertEqual(
            report["overall_assessment"]["status"], "incomplete"
        )

    def test_unexpected_suspicious_crash_is_recorded_and_never_clean(self):
        """A crashing suspicious detector still produces a recorded scan,
        assessed as incomplete - never clean."""
        self.create_baseline()

        with mock.patch.object(
            scan_service,
            "check_suspicious_files",
            side_effect=RuntimeError("detector crashed"),
        ):
            result = self.run_scan()

        self.assertEqual(result["integrity_status"], "success")
        self.assertEqual(result["suspicious_status"], "failed")
        self.assertEqual(result["overall_status"], "incomplete")
        self.assertIn(
            "suspicious_detection",
            [failure["stage"] for failure in result["stage_failures"]],
        )

        # integrity findings and the stage failure are both recorded
        events = get_scan_events(result["scan_id"])
        types = [event["event_type"] for event in events]
        self.assertIn("scan_incomplete", types)
        self.assertTrue(
            any("suspicious_detection" in event["description"]
                for event in self.stage_failure_events(result["scan_id"]))
        )

    def test_recording_failure_propagates(self):
        """When the scan cannot be recorded at all, the error propagates."""
        self.create_baseline()

        with mock.patch.object(
            scan_service,
            "log_scan",
            side_effect=sqlite3.OperationalError("database is gone"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                self.run_scan()

    def test_normal_scan_reports_no_stage_failures(self):
        self.create_baseline()
        result = self.run_scan()
        self.assertEqual(result["overall_status"], "clean")
        self.assertEqual(result["stage_failures"], [])
        self.assertEqual(result["alerts_generated"], 0)
        self.assertIsNotNone(result["report_id"])


if __name__ == "__main__":
    unittest.main()
