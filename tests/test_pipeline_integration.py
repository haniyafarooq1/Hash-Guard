"""Integration tests for the complete scan pipeline (TRD section 11.4).

Runs the real detection modules (create_baseline,
check_integrity, check_suspicious_files) together with the logging, alert and report
modules through the scan orchestrator (backend.services.scan_service).

Scenarios required by the TRD:
 1. Clean scan.
 2. Modified file.
 3. Added file.
 4. Deleted file.
 5. Renamed file.
 6. Newly added executable file.
 7. Multiple simultaneous changes.
 8. Missing baseline.
 9. Tampered baseline.
10. Invalid monitoring directory.
11. Inaccessible file or directory (where reliably testable).
12. Database failure handling.

Every test uses temporary directories and a temporary database, and the
baseline secret key is redirected to a temporary key file so the real
project key is never touched.
"""

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

import baseline_security
from alerts import generate_alerts, get_alerts
from activity_logger import get_scan_by_id, get_scan_events, get_scan_history
from backend.services import scan_service
from backend.storage import database
from report_generator import get_report
from tests.test_helpers import HashGuardTestCase


class PipelineIntegrationTestCase(HashGuardTestCase):
    """Base: temporary monitored folder + temporary baseline secret key."""

    def setUp(self):
        super().setUp()

        # Redirect the HMAC secret key so tests never touch the real one.
        self.original_key_file = baseline_security.KEY_FILE
        self.key_file = self.root / "secret.key"
        baseline_security.KEY_FILE = self.key_file

        # Monitored folder and baseline live in the temp directory too.
        self.monitored = self.root / "Important_Files"
        self.monitored.mkdir()
        self.baseline_file = self.root / "baseline.json"

        (self.monitored / "notes.txt").write_text("Original document")
        (self.monitored / "hello.txt").write_text("Hello Hash Guard!")

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


class TestCleanAndFindings(PipelineIntegrationTestCase):

    def test_clean_scan(self):
        """Scenario 1: baseline matches directory -> clean, no alerts."""
        self.create_baseline()
        result = self.run_scan()

        self.assertEqual(result["integrity_status"], "success")
        self.assertEqual(result["overall_status"], "clean")
        self.assertEqual(result["alerts_generated"], 0)
        self.assertIsNotNone(result["report_id"])

        report = get_report(result["scan_id"])
        self.assertEqual(report["overall_assessment"]["status"], "clean")
        events = get_scan_events(result["scan_id"])
        self.assertEqual([e["event_type"] for e in events], ["scan_recorded"])

    def test_modified_file(self):
        """Scenario 2: content change -> findings, high alert, hashes."""
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Tampered content")
        result = self.run_scan()

        self.assertEqual(result["overall_status"], "findings_detected")
        self.assertEqual(result["integrity_summary"]["modified"], 1)

        events = get_scan_events(result["scan_id"])
        modified = [e for e in events if e["event_type"] == "file_modified"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0]["file_path"], "notes.txt")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "high")
        self.assertEqual(alerts[0]["category"], "integrity")

        report = get_report(result["scan_id"])
        detail = report["integrity_details"]["modified"][0]
        self.assertEqual(detail["path"], "notes.txt")
        self.assertEqual(len(detail["baseline_hash"]), 64)
        self.assertEqual(len(detail["current_hash"]), 64)
        self.assertNotEqual(detail["baseline_hash"], detail["current_hash"])

    def test_added_file(self):
        """Scenario 3: new file -> added event and alert.

        Note: the real suspicious detector flags every newly added file
        with a 'newly added' reason, so one integrity alert (File Added)
        and one suspicious-file alert are expected.
        """
        self.create_baseline()
        (self.monitored / "extra.txt").write_text("New file")
        result = self.run_scan()

        self.assertEqual(result["integrity_summary"]["added"], 1)
        events = get_scan_events(result["scan_id"])
        added = [e for e in events if e["event_type"] == "file_added"]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["file_path"], "extra.txt")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            {a["title"] for a in alerts},
            {"File Added", "Suspicious File Detected"},
        )
        suspicious_alert = next(
            a for a in alerts if a["category"] == "suspicious_file"
        )
        self.assertEqual(suspicious_alert["severity"], "medium")
        self.assertIn("newly added", suspicious_alert["description"].lower())

    def test_deleted_file(self):
        """Scenario 4: removal -> deleted event and high alert."""
        self.create_baseline()
        (self.monitored / "hello.txt").unlink()
        result = self.run_scan()

        self.assertEqual(result["integrity_summary"]["deleted"], 1)
        events = get_scan_events(result["scan_id"])
        deleted = [e for e in events if e["event_type"] == "file_deleted"]
        self.assertEqual(len(deleted), 1)
        self.assertEqual(deleted[0]["file_path"], "hello.txt")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "File Deleted")
        self.assertEqual(alerts[0]["severity"], "high")

    def test_renamed_file(self):
        """Scenario 5: rename -> renamed event with old and new paths."""
        self.create_baseline()
        (self.monitored / "notes.txt").rename(self.monitored / "renamed_notes.txt")
        result = self.run_scan()

        self.assertEqual(result["integrity_summary"]["renamed"], 1)
        events = get_scan_events(result["scan_id"])
        renamed = [e for e in events if e["event_type"] == "file_renamed"]
        self.assertEqual(len(renamed), 1)
        self.assertEqual(renamed[0]["details"]["old_path"], "notes.txt")
        self.assertEqual(renamed[0]["details"]["new_path"], "renamed_notes.txt")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "File Renamed")

    def test_newly_added_executable_file(self):
        """Scenario 6: unexpected.exe -> single high suspicious alert."""
        self.create_baseline()
        (self.monitored / "unexpected.exe").write_text("Harmless dummy file")
        result = self.run_scan()

        self.assertEqual(result["integrity_summary"]["added"], 1)
        self.assertEqual(result["suspicious_summary"]["suspicious_files"], 1)

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        suspicious_alerts = [
            a for a in alerts if a["category"] == "suspicious_file"
        ]
        # FR-14: the file appears in three arrays but yields ONE alert.
        self.assertEqual(len(suspicious_alerts), 1)
        self.assertEqual(suspicious_alerts[0]["severity"], "high")
        self.assertEqual(suspicious_alerts[0]["file_path"], "unexpected.exe")
        # Plus the integrity 'added' alert.
        self.assertEqual(len(alerts), 2)

        report = get_report(result["scan_id"])
        self.assertEqual(len(report["suspicious_details"]), 1)
        self.assertEqual(len(report["suspicious_details"][0]["reasons"]), 3)

    def test_multiple_simultaneous_changes(self):
        """Scenario 7: everything at once, linked to one scan id."""
        (self.monitored / "world.txt").write_text("World")  # third base file
        self.create_baseline()

        (self.monitored / "world.txt").write_text("World changed")  # modified
        (self.monitored / "brand_new.txt").write_text("Added")      # added
        (self.monitored / "hello.txt").unlink()                     # deleted
        # renamed: content must stay identical for hash matching
        (self.monitored / "notes.txt").rename(self.monitored / "notes2.txt")
        result = self.run_scan()

        summary = result["integrity_summary"]
        self.assertEqual(summary["modified"], 1)
        self.assertEqual(summary["renamed"], 1)
        self.assertEqual(summary["added"], 1)
        self.assertEqual(summary["deleted"], 1)

        scan_id = result["scan_id"]
        events = get_scan_events(scan_id)
        types = {e["event_type"] for e in events}
        # brand_new.txt is also flagged by the detector as newly added.
        self.assertEqual(
            types,
            {"scan_recorded", "file_modified", "file_added",
             "file_deleted", "file_renamed", "suspicious_file"},
        )
        self.assertTrue(all(e["scan_id"] == scan_id for e in events))

        alerts = get_alerts(scan_id=scan_id)["items"]
        self.assertEqual(len(alerts), 5)
        self.assertTrue(all(a["scan_id"] == scan_id for a in alerts))

        report = get_report(scan_id)
        self.assertEqual(report["scan_id"], scan_id)


class TestFailureConditions(PipelineIntegrationTestCase):

    def test_missing_baseline(self):
        """Scenario 8: no baseline file -> critical alert, not clean."""
        result = self.run_scan()  # baseline.json does not exist yet

        self.assertEqual(result["integrity_status"], "baseline_unavailable")
        self.assertEqual(result["overall_status"], "baseline_unavailable")
        self.assertEqual(result["baseline_status"], "unavailable_or_unverified")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(alerts[0]["category"], "baseline")

        report = get_report(result["scan_id"])
        self.assertEqual(
            report["overall_assessment"]["status"], "baseline_unavailable"
        )
        self.assertIn(
            "must not be treated as a clean result",
            report["overall_assessment"]["summary"],
        )

    def test_tampered_baseline(self):
        """Scenario 9: edited baseline breaks the signature -> critical."""
        self.create_baseline()
        # Tamper with the baseline content AFTER it was signed.
        content = self.baseline_file.read_text(encoding="utf-8")
        self.baseline_file.write_text(content + "\n", encoding="utf-8")

        result = self.run_scan()

        self.assertEqual(result["integrity_status"], "baseline_unavailable")
        self.assertEqual(result["overall_status"], "baseline_unavailable")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")
        self.assertEqual(
            alerts[0]["title"], "Baseline Unavailable or Authentication Failed"
        )

    def test_invalid_monitoring_directory(self):
        """Scenario 10: missing directory -> recorded, not clean."""
        missing = self.root / "does_not_exist"
        result = scan_service.run_scan(str(missing), str(self.baseline_file))

        self.assertEqual(result["integrity_status"], "invalid_directory")
        self.assertEqual(result["overall_status"], "invalid_directory")
        self.assertEqual(result["baseline_status"], "not_checked")

        alerts = get_alerts(scan_id=result["scan_id"])["items"]
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["category"], "system")
        self.assertEqual(alerts[0]["title"], "Invalid Monitoring Directory")

        report = get_report(result["scan_id"])
        self.assertEqual(
            report["overall_assessment"]["status"], "invalid_directory"
        )

    def test_inaccessible_directory_where_testable(self):
        """Scenario 11: permission errors, when the OS enforces them."""
        self.create_baseline()
        locked = self.monitored / "locked"
        locked.mkdir()
        (locked / "secret.txt").write_text("hidden")
        # Re-create the baseline so it includes the locked directory file.
        self.create_baseline()
        (locked / "secret2.txt").write_text("also hidden")
        os.chmod(locked, 0o000)

        try:
            # Verify the restriction is actually effective for this user.
            try:
                list(locked.iterdir())
                restriction_effective = False
            except OSError:
                restriction_effective = True

            if not restriction_effective:
                self.skipTest(
                    "Permission restrictions are not enforceable for the "
                    "current user (e.g. running as root)."
                )

            result = self.run_scan()
            self.assertEqual(result["integrity_status"], "completed_with_errors")
            self.assertEqual(result["overall_status"], "completed_with_errors")

            events = get_scan_events(result["scan_id"])
            error_events = [e for e in events if e["event_type"] == "scan_error"]
            self.assertGreaterEqual(len(error_events), 1)

            alerts = get_alerts(scan_id=result["scan_id"])["items"]
            system_alerts = [a for a in alerts if a["category"] == "system"]
            self.assertGreaterEqual(len(system_alerts), 1)
        finally:
            os.chmod(locked, 0o755)

    def test_database_failure_handling(self):
        """Scenario 12: a database failure is reported, never hidden."""
        self.create_baseline()

        # Point the storage layer at an impossible location: the
        # configured database path is a DIRECTORY, so SQLite can never
        # open a connection there (missing parent directories, by
        # contrast, are created automatically nowadays).
        database.reset_connections()
        database.set_database_path(str(self.root))

        with self.assertRaises(sqlite3.OperationalError):
            self.run_scan()

        # Restore the working database: the failure must not have
        # produced phantom records.
        database.reset_connections()
        database.set_database_path(str(self.db_file))
        database.init_db()
        self.assertEqual(get_scan_history()["total"], 0)

    def test_scan_events_alerts_and_report_share_scan_id(self):
        """The orchestrator links every record to a single scan id."""
        self.create_baseline()
        (self.monitored / "notes.txt").write_text("Changed")
        (self.monitored / "dropped.exe").write_text("malware-ish")
        result = self.run_scan()

        scan_id = result["scan_id"]
        scan = get_scan_by_id(scan_id)
        self.assertIsNotNone(scan)

        events = get_scan_events(scan_id)
        self.assertGreater(len(events), 1)
        self.assertTrue(all(event["scan_id"] == scan_id for event in events))

        alerts = get_alerts(scan_id=scan_id)["items"]
        self.assertGreater(len(alerts), 1)
        self.assertTrue(all(alert["scan_id"] == scan_id for alert in alerts))

        report = get_report(scan_id)
        self.assertEqual(report["scan_id"], scan_id)
        self.assertEqual(report["scan_info"]["scan_id"], scan_id)

    def test_persistence_across_restart(self):
        """Acceptance criterion 13: history survives a restart."""
        self.create_baseline()
        first = self.run_scan()
        (self.monitored / "notes.txt").write_text("Changed")
        second = self.run_scan()

        # Simulate an application restart.
        database.reset_connections()
        database.set_database_path(str(self.db_file))
        database.init_db()

        history = get_scan_history()
        self.assertEqual(history["total"], 2)
        self.assertEqual(history["items"][0]["scan_id"], second["scan_id"])
        self.assertEqual(history["items"][1]["scan_id"], first["scan_id"])

        # Reports survive as well.
        self.assertIsNotNone(get_report(first["scan_id"]))
        self.assertIsNotNone(get_report(second["scan_id"]))


if __name__ == "__main__":
    unittest.main()
