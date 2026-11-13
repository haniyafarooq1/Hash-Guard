"""Unit tests for report_generator.py (TRD section 11.3).

Scenarios required by the TRD:
 1. Generate a clean scan report.
 2. Generate a report containing modified files.
 3. Generate a report containing added and deleted files.
 4. Generate a report containing renamed files.
 5. Include suspicious-file findings.
 6. Include security alerts.
 7. Include scan errors.
 8. Generate a report for baseline-unavailable status.
 9. Generate a report for an invalid directory.
10. Retrieve the stored report by scan ID.
Plus: report snapshot immutability (FR-22), controlled regeneration,
JSON export (FR-20), PDF export (FR-21) and failure isolation.
"""

import json
import unittest

from activity_logger import log_scan
from alerts import generate_alerts, update_alert_status
from report_generator import (
    ReportNotFoundError,
    export_report_json,
    export_report_pdf,
    generate_report,
    get_report,
    list_reports,
)
from tests.test_helpers import (
    HashGuardTestCase,
    make_integrity_result,
    make_suspicious_result,
)


def process_scan(integrity, suspicious=None):
    """Run the full logging -> alerts -> report flow for synthetic results."""
    record = log_scan(integrity, suspicious)
    scan_id = record["scan_id"]
    alerts = generate_alerts(integrity, suspicious, scan_id)
    report = generate_report(integrity, suspicious, alerts, scan_id)
    return scan_id, alerts, report


class TestReportGeneration(HashGuardTestCase):

    def test_clean_scan_report(self):
        """Scenario 1: clean report, never with alerts."""
        scan_id, alerts, report = process_scan(
            make_integrity_result(), make_suspicious_result()
        )
        self.assertEqual(alerts, [])
        self.assertEqual(report["overall_assessment"]["status"], "clean")
        self.assertIn("completed successfully", report["overall_assessment"]["summary"])
        self.assertEqual(report["scan_info"]["overall_status"], "clean")
        self.assertEqual(report["scan_info"]["baseline_status"], "verified")
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["integrity_details"]["modified"], [])
        self.assertEqual(report["suspicious_details"], [])
        self.assertEqual(report["errors"], [])

    def test_report_with_modified_files(self):
        """Scenario 2: modified files with both hashes."""
        integrity = make_integrity_result(
            modified=[{
                "path": "documents/report.txt",
                "baseline_hash": "a" * 64,
                "current_hash": "b" * 64,
            }]
        )
        _, _, report = process_scan(integrity, make_suspicious_result())

        self.assertEqual(
            report["overall_assessment"]["status"], "findings_detected"
        )
        modified = report["integrity_details"]["modified"]
        self.assertEqual(len(modified), 1)
        self.assertEqual(modified[0]["path"], "documents/report.txt")
        self.assertEqual(modified[0]["baseline_hash"], "a" * 64)
        self.assertEqual(modified[0]["current_hash"], "b" * 64)
        self.assertEqual(report["integrity_summary"]["modified"], 1)

    def test_report_with_added_and_deleted_files(self):
        """Scenario 3: added and deleted file details."""
        integrity = make_integrity_result(
            added=[{"path": "new_file.txt", "current_hash": "c" * 64}],
            deleted=[{"path": "gone.txt", "baseline_hash": "d" * 64}],
        )
        _, _, report = process_scan(integrity, make_suspicious_result())

        self.assertEqual(len(report["integrity_details"]["added"]), 1)
        self.assertEqual(
            report["integrity_details"]["added"][0]["current_hash"], "c" * 64
        )
        self.assertEqual(len(report["integrity_details"]["deleted"]), 1)
        self.assertEqual(
            report["integrity_details"]["deleted"][0]["baseline_hash"], "d" * 64
        )

    def test_report_with_renamed_files(self):
        """Scenario 4: renamed files with old path, new path and hash."""
        integrity = make_integrity_result(
            renamed=[{
                "old_path": "old_name.txt",
                "new_path": "new_name.txt",
                "sha256": "e" * 64,
            }]
        )
        _, _, report = process_scan(integrity, make_suspicious_result())

        renamed = report["integrity_details"]["renamed"]
        self.assertEqual(len(renamed), 1)
        self.assertEqual(renamed[0]["old_path"], "old_name.txt")
        self.assertEqual(renamed[0]["new_path"], "new_name.txt")
        self.assertEqual(renamed[0]["sha256"], "e" * 64)

    def test_report_includes_suspicious_findings(self):
        """Scenario 5: suspicious details with reasons and severity."""
        integrity = make_integrity_result(
            added=[{"path": "unexpected.exe", "current_hash": "f" * 64}]
        )
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "unexpected.exe",
                "extension": ".exe",
                "reasons": [
                    "File has a potentially risky extension.",
                    "File is executable or has an executable file type.",
                ],
                "severity": "high",
            }],
            executable_files=[{"path": "unexpected.exe", "extension": ".exe"}],
            newly_added_files=[{"path": "unexpected.exe", "reason": "new"}],
        )
        _, _, report = process_scan(integrity, suspicious)

        self.assertEqual(report["suspicious_summary"]["suspicious_files"], 1)
        details = report["suspicious_details"]
        self.assertEqual(len(details), 1)
        self.assertEqual(details[0]["path"], "unexpected.exe")
        self.assertEqual(details[0]["extension"], ".exe")
        self.assertEqual(details[0]["severity"], "high")
        self.assertEqual(len(details[0]["reasons"]), 2)

    def test_report_includes_security_alerts(self):
        """Scenario 6: alert snapshot inside the report."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        scan_id, alerts, report = process_scan(integrity, make_suspicious_result())

        self.assertEqual(len(alerts), 1)
        report_alerts = report["alerts"]
        self.assertEqual(len(report_alerts), 1)
        self.assertEqual(report_alerts[0]["title"], "File Modified")
        self.assertEqual(report_alerts[0]["severity"], "high")
        self.assertEqual(report_alerts[0]["category"], "integrity")
        self.assertEqual(report_alerts[0]["file_path"], "a.txt")
        self.assertEqual(report_alerts[0]["status"], "unread")

    def test_report_includes_scan_errors(self):
        """Scenario 7: errors with their source."""
        integrity = make_integrity_result(
            status="completed_with_errors",
            errors=[{"path": "/tmp/monitored/locked.txt",
                     "message": "Permission denied"}],
        )
        suspicious = make_suspicious_result(
            status="completed_with_errors",
            errors=[{"path": "/tmp/monitored/other.txt",
                     "message": "stat failed"}],
        )
        _, _, report = process_scan(integrity, suspicious)

        self.assertEqual(
            report["overall_assessment"]["status"], "completed_with_errors"
        )
        sources = {error["source"] for error in report["errors"]}
        self.assertEqual(
            sources, {"integrity_checker", "suspicious_detector"}
        )
        self.assertEqual(len(report["errors"]), 2)

    def test_report_for_baseline_unavailable(self):
        """Scenario 8: baseline failure is reported, never clean."""
        integrity = make_integrity_result(
            status="baseline_unavailable",
            errors=[{"path": "/tmp/baseline.json",
                     "message": "Baseline unavailable or authentication failed."}],
        )
        scan_id, alerts, report = process_scan(
            integrity, make_suspicious_result()
        )

        self.assertEqual(
            report["overall_assessment"]["status"], "baseline_unavailable"
        )
        self.assertIn("must not be treated as a clean result",
                      report["overall_assessment"]["summary"])
        self.assertEqual(report["scan_info"]["baseline_status"],
                         "unavailable_or_unverified")
        # FR-09: a critical alert was generated for it.
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "critical")

    def test_report_for_invalid_directory(self):
        """Scenario 9: invalid directory report."""
        integrity = make_integrity_result(
            status="invalid_directory",
            errors=[{"path": "/nowhere",
                     "message": "Invalid or unavailable monitoring directory."}],
        )
        _, _, report = process_scan(
            integrity, make_suspicious_result(status="invalid_directory")
        )

        self.assertEqual(report["overall_assessment"]["status"], "invalid_directory")
        self.assertEqual(report["scan_info"]["baseline_status"], "not_checked")
        self.assertIn("could not be performed",
                      report["overall_assessment"]["summary"])

    def test_retrieve_stored_report_by_scan_id(self):
        """Scenario 10: round-trip through the database."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        scan_id, _, report = process_scan(integrity, make_suspicious_result())

        stored = get_report(scan_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["scan_id"], scan_id)
        self.assertEqual(stored["report_id"], report["report_id"])
        self.assertEqual(
            stored["overall_assessment"]["status"], "findings_detected"
        )
        self.assertEqual(
            stored["integrity_details"]["modified"][0]["path"], "a.txt"
        )
        self.assertIsNone(get_report(99999))

        listing = list_reports()
        self.assertEqual(listing["total"], 1)
        self.assertEqual(listing["items"][0]["scan_id"], scan_id)
        self.assertEqual(listing["items"][0]["overall_status"], "findings_detected")


class TestReportSemantics(HashGuardTestCase):

    def test_report_is_a_snapshot(self):
        """FR-22 / 10.6: later alert-status changes never rewrite history."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        scan_id, alerts, report = process_scan(integrity, make_suspicious_result())

        # User marks the alert as read after the report was generated.
        update_alert_status(alerts[0]["alert_id"], "read")

        stored = get_report(scan_id)
        self.assertEqual(stored["alerts"][0]["status"], "unread")

    def test_regeneration_replaces_snapshot_in_place(self):
        """One report row per scan; regeneration is a controlled update."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        record = log_scan(integrity, make_suspicious_result())
        scan_id = record["scan_id"]

        alerts = generate_alerts(integrity, make_suspicious_result(), scan_id)
        first = generate_report(integrity, make_suspicious_result(), alerts, scan_id)
        second = generate_report(integrity, make_suspicious_result(), alerts, scan_id)

        self.assertEqual(first["report_id"], second["report_id"])
        listing = list_reports()
        self.assertEqual(listing["total"], 1)

    def test_report_requires_recorded_scan(self):
        with self.assertRaises(ValueError):
            generate_report(
                make_integrity_result(), make_suspicious_result(), [], 999
            )

    def test_report_failure_does_not_lose_scan_data(self):
        """TRD 10.5: a failed report generation leaves the scan intact."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        record = log_scan(integrity, make_suspicious_result())

        with self.assertRaises(ValueError):
            generate_report(integrity, make_suspicious_result(), [], 999)

        # The scan and its events are still there.
        from activity_logger import get_scan_by_id, get_scan_events
        self.assertIsNotNone(get_scan_by_id(record["scan_id"]))
        self.assertEqual(len(get_scan_events(record["scan_id"])), 2)


class TestReportExports(HashGuardTestCase):

    def _make_report(self):
        integrity = make_integrity_result(
            modified=[{
                "path": "documents/report.txt",
                "baseline_hash": "a" * 64,
                "current_hash": "b" * 64,
            }],
            renamed=[{
                "old_path": "old.txt", "new_path": "new.txt", "sha256": "e" * 64,
            }],
        )
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "unexpected.exe", "extension": ".exe",
                "reasons": ["File has a potentially risky extension."],
                "severity": "high",
            }],
        )
        scan_id, alerts, report = process_scan(integrity, suspicious)
        return scan_id, report

    def test_export_report_json(self):
        """FR-20: JSON export contains the full structured report."""
        scan_id, report = self._make_report()
        output = self.root / "exported_report.json"
        path = export_report_json(scan_id, str(output))

        self.assertTrue(path.exists())
        exported = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(exported["scan_id"], scan_id)
        self.assertEqual(exported["report_id"], report["report_id"])
        self.assertEqual(
            exported["integrity_details"]["modified"][0]["path"],
            "documents/report.txt",
        )
        self.assertEqual(len(exported["alerts"]), 3)

    def test_export_report_pdf(self):
        """FR-21: PDF export reuses the same report data."""
        scan_id, report = self._make_report()
        output = self.root / "exported_report.pdf"
        path = export_report_pdf(scan_id, str(output))

        self.assertTrue(path.exists())
        content = path.read_bytes()
        self.assertGreater(len(content), 1000)
        self.assertTrue(content.startswith(b"%PDF"))

    def test_export_missing_report_raises(self):
        with self.assertRaises(ReportNotFoundError):
            export_report_json(999, str(self.root / "x.json"))
        with self.assertRaises(ReportNotFoundError):
            export_report_pdf(999, str(self.root / "x.pdf"))


if __name__ == "__main__":
    unittest.main()
