"""Unit tests for activity_logger.py (TRD section 11.1).

Scenarios required by the TRD:
 1. Record a successful clean scan.
 2. Record a scan with modified files.
 3. Record added, deleted and renamed files.
 4. Record suspicious-file findings.
 5. Record a baseline-unavailable result.
 6. Record an invalid-directory result.
 7. Record a scan with errors.
 8. Retrieve scan history.
 9. Retrieve events for a specific scan.
10. Filter and paginate activity logs.
Plus: timestamp handling (FR-07), derived assessments (FR-19),
persistence across connections, and input validation.
"""

import unittest

from activity_logger import (
    append_scan_event,
    derive_baseline_status,
    derive_overall_status,
    get_activity_logs,
    get_event_by_id,
    get_scan_by_id,
    get_scan_events,
    get_scan_history,
    log_scan,
)
from backend.storage import database
from tests.test_helpers import (
    HashGuardTestCase,
    make_integrity_result,
    make_suspicious_result,
)


class TestRecordScans(HashGuardTestCase):

    def test_record_successful_clean_scan(self):
        """Scenario 1: a clean scan is recorded with overall status clean."""
        record = log_scan(
            make_integrity_result(),
            make_suspicious_result(),
        )
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["overall_status"], "clean")
        self.assertEqual(record["scan_id"], 1)

        scan = get_scan_by_id(1)
        self.assertEqual(scan["integrity_status"], "success")
        self.assertEqual(scan["suspicious_status"], "success")
        self.assertEqual(scan["baseline_status"], "verified")
        self.assertEqual(scan["overall_status"], "clean")
        self.assertEqual(scan["scan_time"], "2026-11-07T12:00:00+05:00")

        events = get_scan_events(1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "scan_recorded")
        self.assertEqual(events[0]["severity"], "info")

    def test_record_scan_with_modified_files(self):
        """Scenario 2: modified files become file_modified events."""
        integrity = make_integrity_result(
            modified=[{
                "path": "documents/report.txt",
                "baseline_hash": "a" * 64,
                "current_hash": "b" * 64,
            }]
        )
        record = log_scan(integrity, make_suspicious_result())
        self.assertEqual(record["overall_status"], "findings_detected")

        events = get_scan_events(record["scan_id"])
        modified_events = [e for e in events if e["event_type"] == "file_modified"]
        self.assertEqual(len(modified_events), 1)
        event = modified_events[0]
        self.assertEqual(event["file_path"], "documents/report.txt")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["source"], "integrity_checker")
        self.assertEqual(event["details"]["baseline_hash"], "a" * 64)
        self.assertEqual(event["details"]["current_hash"], "b" * 64)

    def test_record_added_deleted_and_renamed_files(self):
        """Scenario 3: added / deleted / renamed events with details."""
        integrity = make_integrity_result(
            added=[{"path": "new.txt", "current_hash": "c" * 64}],
            deleted=[{"path": "gone.txt", "baseline_hash": "d" * 64}],
            renamed=[{
                "old_path": "old_name.txt",
                "new_path": "new_name.txt",
                "sha256": "e" * 64,
            }],
        )
        record = log_scan(integrity, make_suspicious_result())

        events = get_scan_events(record["scan_id"])
        by_type = {event["event_type"]: event for event in events}

        self.assertIn("file_added", by_type)
        self.assertEqual(by_type["file_added"]["severity"], "medium")
        self.assertEqual(by_type["file_added"]["details"]["current_hash"], "c" * 64)

        self.assertIn("file_deleted", by_type)
        self.assertEqual(by_type["file_deleted"]["severity"], "high")
        self.assertEqual(by_type["file_deleted"]["details"]["baseline_hash"], "d" * 64)

        # FR-02: a renamed file must record both old and new paths.
        self.assertIn("file_renamed", by_type)
        self.assertEqual(by_type["file_renamed"]["details"]["old_path"], "old_name.txt")
        self.assertEqual(by_type["file_renamed"]["details"]["new_path"], "new_name.txt")
        self.assertEqual(by_type["file_renamed"]["details"]["sha256"], "e" * 64)
        self.assertEqual(by_type["file_renamed"]["file_path"], "new_name.txt")

    def test_record_suspicious_findings(self):
        """Scenario 4: suspicious findings recorded from suspicious_files only.

        The file also appears in executable_files and newly_added_files,
        which must NOT create duplicate events (FR-03).
        """
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "unexpected.exe",
                "extension": ".exe",
                "reasons": [
                    "File has a potentially risky extension.",
                    "File is executable or has an executable file type.",
                    "File was newly added after baseline creation.",
                ],
                "severity": "high",
            }],
            executable_files=[{"path": "unexpected.exe", "extension": ".exe"}],
            newly_added_files=[{
                "path": "unexpected.exe",
                "reason": "File was not present in the authenticated baseline.",
            }],
        )
        record = log_scan(make_integrity_result(), suspicious)
        self.assertEqual(record["overall_status"], "findings_detected")

        events = get_scan_events(record["scan_id"])
        suspicious_events = [e for e in events if e["event_type"] == "suspicious_file"]
        self.assertEqual(len(suspicious_events), 1)

        event = suspicious_events[0]
        self.assertEqual(event["file_path"], "unexpected.exe")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["source"], "suspicious_detector")
        self.assertEqual(len(event["details"]["reasons"]), 3)
        self.assertTrue(event["details"]["executable"])
        self.assertTrue(event["details"]["newly_added"])

    def test_record_baseline_unavailable(self):
        """Scenario 5: baseline failure recorded, never clean."""
        integrity = make_integrity_result(
            status="baseline_unavailable",
            errors=[{"path": "/tmp/baseline.json",
                     "message": "Baseline unavailable or authentication failed."}],
        )
        record = log_scan(integrity, make_suspicious_result())

        self.assertEqual(record["overall_status"], "baseline_unavailable")
        scan = get_scan_by_id(record["scan_id"])
        self.assertEqual(scan["baseline_status"], "unavailable_or_unverified")

        events = get_scan_events(record["scan_id"])
        types = [event["event_type"] for event in events]
        self.assertIn("baseline_unavailable", types)
        baseline_event = next(
            e for e in events if e["event_type"] == "baseline_unavailable"
        )
        self.assertEqual(baseline_event["severity"], "critical")
        # The baseline failure is not duplicated as a generic scan_error.
        self.assertNotIn("scan_error", types)

    def test_record_invalid_directory(self):
        """Scenario 6: invalid directory recorded with not_checked baseline."""
        integrity = make_integrity_result(
            status="invalid_directory",
            errors=[{"path": "/nowhere", "message": "Invalid or unavailable monitoring directory."}],
        )
        record = log_scan(integrity, make_suspicious_result(status="invalid_directory"))

        self.assertEqual(record["overall_status"], "invalid_directory")
        scan = get_scan_by_id(record["scan_id"])
        self.assertEqual(scan["baseline_status"], "not_checked")

        events = get_scan_events(record["scan_id"])
        invalid_events = [
            e for e in events if e["event_type"] == "invalid_directory"
        ]
        self.assertEqual(len(invalid_events), 2)  # one per reporting module
        self.assertEqual(
            {event["source"] for event in invalid_events},
            {"integrity_checker", "suspicious_detector"},
        )

    def test_record_scan_with_errors(self):
        """Scenario 7: errors from both modules recorded with their source."""
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
        record = log_scan(integrity, suspicious)
        self.assertEqual(record["overall_status"], "completed_with_errors")

        events = get_scan_events(record["scan_id"])
        error_events = [e for e in events if e["event_type"] == "scan_error"]
        self.assertEqual(len(error_events), 2)
        self.assertEqual(
            {event["source"] for event in error_events},
            {"integrity_checker", "suspicious_detector"},
        )

    def test_failed_scan_must_also_be_recorded(self):
        """FR-01: every attempt is recorded, including failed ones."""
        record = log_scan(make_integrity_result(status="baseline_unavailable"))
        self.assertIsNotNone(record["scan_id"])
        self.assertEqual(get_scan_history()["total"], 1)


class TestRetrieval(HashGuardTestCase):

    def _seed(self, count=3):
        scan_ids = []
        for index in range(count):
            integrity = make_integrity_result(
                scan_time="2026-11-0{}T12:00:00+05:00".format(index + 1),
                modified=[{"path": "file{}.txt".format(index),
                           "baseline_hash": "a" * 64,
                           "current_hash": "b" * 64}] if index == 0 else None,
                added=[{"path": "extra{}.txt".format(index),
                        "current_hash": "c" * 64}] if index == 1 else None,
            )
            suspicious = make_suspicious_result(
                suspicious_files=[{
                    "path": "bad{}.exe".format(index), "extension": ".exe",
                    "reasons": ["File has a potentially risky extension."],
                    "severity": "high",
                }] if index == 2 else None,
            )
            record = log_scan(integrity, suspicious)
            scan_ids.append(record["scan_id"])
        return scan_ids

    def test_retrieve_scan_history(self):
        """Scenario 8: history with pagination and derived fields."""
        self._seed(3)
        history = get_scan_history(limit=50, offset=0)
        self.assertEqual(history["total"], 3)
        self.assertEqual(len(history["items"]), 3)
        # Newest first
        self.assertEqual(history["items"][0]["scan_id"], 3)
        # Derived counts are exposed for the list views
        first = history["items"][0]
        self.assertEqual(first["alert_count"], 0)
        self.assertEqual(first["event_count"], 2)  # scan_recorded + suspicious

        page = get_scan_history(limit=2, offset=2)
        self.assertEqual(page["total"], 3)
        self.assertEqual(len(page["items"]), 1)
        self.assertEqual(page["items"][0]["scan_id"], 1)

    def test_retrieve_events_for_specific_scan(self):
        """Scenario 9: events of one scan, and individual event lookup."""
        scan_ids = self._seed(3)
        events = get_scan_events(scan_ids[0])
        self.assertEqual(
            [event["event_type"] for event in events],
            ["scan_recorded", "file_modified"],
        )
        event = get_event_by_id(events[1]["event_id"])
        self.assertEqual(event["event_type"], "file_modified")
        self.assertIsNone(get_event_by_id(99999))

    def test_filter_and_paginate_activity_logs(self):
        """Scenario 10: filtering by type, severity, scan, date + pagination."""
        self._seed(3)

        # Filter by event type
        modified = get_activity_logs(event_type="file_modified")
        self.assertEqual(modified["total"], 1)
        self.assertEqual(modified["items"][0]["file_path"], "file0.txt")

        # Filter by severity
        high = get_activity_logs(severity="high")
        self.assertEqual(
            sorted(item["event_type"] for item in high["items"]),
            ["file_modified", "suspicious_file"],
        )

        # Filter by scan id
        scan_two = get_activity_logs(scan_id=2)
        self.assertEqual(scan_two["total"], 2)
        self.assertTrue(
            all(item["scan_id"] == 2 for item in scan_two["items"])
        )

        # Date range: only scans from 2026-11-02 onwards
        later = get_activity_logs(
            start_date="2026-11-02", end_date="2026-11-03"
        )
        self.assertEqual(later["total"], 4)  # scans 2 and 3, 2 events each

        # Date range that excludes everything
        nothing = get_activity_logs(start_date="2020-01-01", end_date="2020-01-02")
        self.assertEqual(nothing["total"], 0)

        # Pagination
        page_one = get_activity_logs(limit=3, offset=0)
        self.assertEqual(len(page_one["items"]), 3)
        page_two = get_activity_logs(limit=3, offset=3)
        self.assertEqual(page_two["total"], 6)
        self.assertEqual(len(page_two["items"]), 3)

    def test_invalid_filters_and_pagination_rejected(self):
        with self.assertRaises(ValueError):
            get_activity_logs(limit=0)
        with self.assertRaises(ValueError):
            get_activity_logs(limit=501)
        with self.assertRaises(ValueError):
            get_activity_logs(offset=-1)
        with self.assertRaises(ValueError):
            get_activity_logs(start_date="not-a-date")

    def test_invalid_integrity_result_rejected(self):
        with self.assertRaises(ValueError):
            log_scan(None)
        with self.assertRaises(ValueError):
            log_scan("not a dict")
        with self.assertRaises(ValueError):
            log_scan(make_integrity_result(), "not a dict")


class TestTimestampsAndAssessments(HashGuardTestCase):

    def test_timestamps_preserve_original_offset(self):
        """FR-07: the integrity scan_time is the canonical timestamp."""
        integrity = make_integrity_result(scan_time="2026-11-07T12:00:00+05:00")
        suspicious = make_suspicious_result(scan_time="2026-11-07T12:00:01+05:00")
        record = log_scan(integrity, suspicious)

        scan = get_scan_by_id(record["scan_id"])
        self.assertEqual(scan["scan_time"], "2026-11-07T12:00:00+05:00")

        for event in get_scan_events(record["scan_id"]):
            self.assertEqual(event["timestamp"], "2026-11-07T12:00:00+05:00")

        # The suspicious detector's own timestamp is preserved in its result.
        self.assertEqual(
            scan["suspicious_result"]["scan_time"],
            "2026-11-07T12:00:01+05:00",
        )

    def test_derive_baseline_status(self):
        self.assertEqual(
            derive_baseline_status(make_integrity_result(status="success")),
            "verified",
        )
        self.assertEqual(
            derive_baseline_status(
                make_integrity_result(status="completed_with_errors")
            ),
            "verified",
        )
        self.assertEqual(
            derive_baseline_status(
                make_integrity_result(status="baseline_unavailable")
            ),
            "unavailable_or_unverified",
        )
        self.assertEqual(
            derive_baseline_status(
                make_integrity_result(status="invalid_directory")
            ),
            "not_checked",
        )

    def test_derive_overall_status_priority_rules(self):
        """FR-19 priority order."""
        # Priority 1: invalid directory
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(status="invalid_directory"),
                make_suspicious_result(status="invalid_directory"),
            ),
            "invalid_directory",
        )
        # Priority 2: baseline unavailable (even with suspicious findings)
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(status="baseline_unavailable"),
                make_suspicious_result(
                    suspicious_files=[{
                        "path": "x.exe", "extension": ".exe",
                        "reasons": ["r"], "severity": "high",
                    }]
                ),
            ),
            "baseline_unavailable",
        )
        # Priority 3: errors beat findings
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(
                    status="completed_with_errors",
                    modified=[{"path": "a", "baseline_hash": "1", "current_hash": "2"}],
                ),
                make_suspicious_result(),
            ),
            "completed_with_errors",
        )
        # Suspicious-detector errors also lead to completed_with_errors
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(),
                make_suspicious_result(
                    status="completed_with_errors",
                    errors=[{"path": "p", "message": "m"}],
                ),
            ),
            "completed_with_errors",
        )
        # Priority 4: findings
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(added=[{"path": "n", "current_hash": "h"}]),
                make_suspicious_result(),
            ),
            "findings_detected",
        )
        # Priority 5: clean only when everything succeeded
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(), make_suspicious_result()
            ),
            "clean",
        )

    def test_original_results_are_preserved(self):
        """TRD 10.1: the original result dictionaries are stored as-is."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "x", "current_hash": "y"}]
        )
        integrity_before = dict(integrity)
        suspicious = make_suspicious_result()
        suspicious_before = dict(suspicious)

        log_scan(integrity, suspicious)

        # The caller's dictionaries were not modified.
        self.assertEqual(integrity, integrity_before)
        self.assertEqual(suspicious, suspicious_before)

        # The stored copies round-trip.
        scan = get_scan_by_id(1)
        self.assertEqual(scan["integrity_result"]["modified"][0]["path"], "a.txt")
        self.assertEqual(scan["suspicious_result"]["status"], "success")

    def test_persistence_across_connections(self):
        """Acceptance criterion 13: data survives a 'restart'."""
        log_scan(make_integrity_result(), make_suspicious_result())
        # Simulate an application restart: close and reopen the database.
        database.reset_connections()
        database.set_database_path(str(self.db_file))
        database.init_db()

        history = get_scan_history()
        self.assertEqual(history["total"], 1)
        self.assertEqual(history["items"][0]["overall_status"], "clean")


class TestOverallStatusRequiresBothStages(HashGuardTestCase):
    """A scan is only clean when BOTH detection stages ran and finished."""

    def test_missing_suspicious_result_is_never_clean(self):
        """No suspicious result -> the scan is incomplete, never clean."""
        self.assertEqual(
            derive_overall_status(make_integrity_result(), None),
            "incomplete",
        )

    def test_not_started_suspicious_status_is_never_clean(self):
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(),
                make_suspicious_result(status="not_started"),
            ),
            "incomplete",
        )

    def test_failed_suspicious_status_is_never_clean(self):
        """A crashed stage outranks its own error entries and findings."""
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(),
                make_suspicious_result(
                    status="failed",
                    errors=[{"path": "p", "message": "boom"}],
                ),
            ),
            "incomplete",
        )

    def test_unknown_suspicious_status_is_never_clean(self):
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(),
                make_suspicious_result(status="something_new"),
            ),
            "incomplete",
        )

    def test_missing_suspicious_status_key_is_never_clean(self):
        suspicious = make_suspicious_result()
        del suspicious["status"]
        self.assertEqual(
            derive_overall_status(make_integrity_result(), suspicious),
            "incomplete",
        )

    def test_failed_integrity_status_is_never_clean(self):
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(
                    status="failed",
                    errors=[{"path": "/tmp/x", "message": "crash"}],
                ),
                make_suspicious_result(),
            ),
            "incomplete",
        )

    def test_findings_with_missing_suspicious_stage_stay_incomplete(self):
        """Real findings do not mask the fact that the scan did not finish."""
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(
                    modified=[{
                        "path": "a.txt",
                        "baseline_hash": "1",
                        "current_hash": "2",
                    }]
                ),
                None,
            ),
            "incomplete",
        )

    def test_completed_with_errors_suspicious_is_not_incomplete(self):
        """A stage that ran and finished with errors keeps its meaning."""
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(),
                make_suspicious_result(
                    status="completed_with_errors",
                    errors=[{"path": "p", "message": "m"}],
                ),
            ),
            "completed_with_errors",
        )

    def test_both_stages_success_is_still_clean(self):
        self.assertEqual(
            derive_overall_status(
                make_integrity_result(), make_suspicious_result()
            ),
            "clean",
        )


class TestIncompleteScanRecording(HashGuardTestCase):
    """Incomplete scans are recorded with a visible reason, never clean."""

    def test_missing_suspicious_stage_records_incomplete_scan(self):
        record = log_scan(make_integrity_result())
        self.assertEqual(record["overall_status"], "incomplete")

        scan = get_scan_by_id(record["scan_id"])
        self.assertEqual(scan["overall_status"], "incomplete")
        self.assertIsNone(scan["suspicious_status"])

        events = get_scan_events(record["scan_id"])
        types = [event["event_type"] for event in events]
        self.assertIn("scan_incomplete", types)
        incomplete_event = next(
            event for event in events
            if event["event_type"] == "scan_incomplete"
        )
        self.assertEqual(incomplete_event["severity"], "high")
        self.assertIn("did not run", incomplete_event["description"])

    def test_failed_suspicious_stage_records_incomplete_scan(self):
        suspicious = make_suspicious_result(
            status="failed",
            errors=[{"path": "monitored", "message": "detector crashed"}],
        )
        record = log_scan(make_integrity_result(), suspicious)
        self.assertEqual(record["overall_status"], "incomplete")

        events = get_scan_events(record["scan_id"])
        incomplete_event = next(
            event for event in events
            if event["event_type"] == "scan_incomplete"
        )
        self.assertIn(
            "did not complete (status: failed)",
            incomplete_event["description"],
        )
        # the stage's own error is still recorded as a scan_error event
        error_events = [
            event for event in events if event["event_type"] == "scan_error"
        ]
        self.assertEqual(len(error_events), 1)


class TestAppendScanEvent(HashGuardTestCase):
    """append_scan_event() lets the orchestrator record stage failures."""

    def setUp(self):
        super().setUp()
        self.record = log_scan(
            make_integrity_result(), make_suspicious_result()
        )
        self.scan_id = self.record["scan_id"]

    def test_append_event_is_stored_and_returned(self):
        event = append_scan_event(
            self.scan_id,
            event_type="scan_error",
            source="system",
            description="alert_generation stage failed: boom",
            severity="high",
            details={"stage": "alert_generation", "error": "boom"},
        )
        self.assertIsNotNone(event["event_id"])
        self.assertEqual(event["scan_id"], self.scan_id)
        self.assertEqual(event["event_type"], "scan_error")
        self.assertEqual(event["source"], "system")
        self.assertEqual(event["severity"], "high")
        self.assertEqual(event["details"]["stage"], "alert_generation")

        stored = get_event_by_id(event["event_id"])
        self.assertEqual(
            stored["description"], "alert_generation stage failed: boom"
        )

    def test_append_event_validates_its_arguments(self):
        with self.assertRaises(ValueError):
            append_scan_event(self.scan_id, "not_a_type", "system", "d")
        with self.assertRaises(ValueError):
            append_scan_event(self.scan_id, "scan_error", "nobody", "d")
        with self.assertRaises(ValueError):
            append_scan_event(
                self.scan_id, "scan_error", "system", "d", severity="extreme"
            )
        with self.assertRaises(ValueError):
            append_scan_event(self.scan_id, "scan_error", "system", "  ")
        with self.assertRaises(ValueError):
            append_scan_event(99999, "scan_error", "system", "d")


if __name__ == "__main__":
    unittest.main()
