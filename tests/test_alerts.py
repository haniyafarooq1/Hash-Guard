"""Unit tests for alerts.py (TRD section 11.2).

Scenarios required by the TRD:
 1. Generate a high-severity modified-file alert.
 2. Generate an added-file alert.
 3. Generate a deleted-file alert.
 4. Generate a renamed-file alert.
 5. Generate a suspicious executable alert.
 6. Generate an alert for a risky extension.
 7. Generate a critical baseline-unavailable alert.
 8. Generate an alert for invalid directory or scan errors.
 9. Update alert status to read and dismissed.
10. Prevent duplicate alerts for the same scan.
Plus: overlapping suspicious arrays must not duplicate alerts (FR-14),
clean scans generate no alerts (FR-16), configurable severities (FR-08)
and alert filtering (FR-15).
"""

import unittest

from activity_logger import log_scan
from alerts import (
    generate_alerts,
    get_alert_by_id,
    get_severity_config,
    get_alert_summary,
    get_alerts,
    reset_severity_config,
    set_severity_config,
    update_alert_status,
)
from tests.test_helpers import (
    HashGuardTestCase,
    make_integrity_result,
    make_suspicious_result,
)


def record_scan(integrity, suspicious=None):
    """Record a scan and return its scan id."""
    record = log_scan(integrity, suspicious)
    return record["scan_id"]


class TestAlertGeneration(HashGuardTestCase):

    def test_modified_file_alert_is_high_severity(self):
        """Scenario 1."""
        integrity = make_integrity_result(
            modified=[{
                "path": "documents/report.txt",
                "baseline_hash": "a" * 64,
                "current_hash": "b" * 64,
            }]
        )
        alerts = generate_alerts(integrity, make_suspicious_result(), record_scan(integrity))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["title"], "File Modified")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["category"], "integrity")
        self.assertEqual(alert["file_path"], "documents/report.txt")
        self.assertEqual(alert["status"], "unread")

    def test_added_file_alert(self):
        """Scenario 2."""
        integrity = make_integrity_result(
            added=[{"path": "new_file.txt", "current_hash": "c" * 64}]
        )
        alerts = generate_alerts(integrity, make_suspicious_result(), record_scan(integrity))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "File Added")
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(alerts[0]["category"], "integrity")

    def test_deleted_file_alert(self):
        """Scenario 3."""
        integrity = make_integrity_result(
            deleted=[{"path": "gone.txt", "baseline_hash": "d" * 64}]
        )
        alerts = generate_alerts(integrity, make_suspicious_result(), record_scan(integrity))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["title"], "File Deleted")
        self.assertEqual(alerts[0]["severity"], "high")

    def test_renamed_file_alert(self):
        """Scenario 4."""
        integrity = make_integrity_result(
            renamed=[{
                "old_path": "old.txt", "new_path": "new.txt", "sha256": "e" * 64,
            }]
        )
        alerts = generate_alerts(integrity, make_suspicious_result(), record_scan(integrity))

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["title"], "File Renamed")
        self.assertEqual(alert["severity"], "medium")
        self.assertEqual(alert["file_path"], "new.txt")
        self.assertIn("old.txt", alert["description"])

    def test_suspicious_executable_alert(self):
        """Scenario 5: executable file -> high severity suspicious alert."""
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
        )
        scan_id = record_scan(integrity)
        alerts = generate_alerts(integrity, suspicious, scan_id)

        suspicious_alerts = [
            a for a in alerts if a["category"] == "suspicious_file"
        ]
        self.assertEqual(len(suspicious_alerts), 1)
        self.assertEqual(suspicious_alerts[0]["severity"], "high")
        self.assertIn("risky extension", suspicious_alerts[0]["description"])

    def test_risky_extension_alert(self):
        """Scenario 6: risky but non-executable -> medium severity."""
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "script.js",
                "extension": ".js",
                "reasons": ["File has a potentially risky extension."],
                "severity": "medium",
            }],
        )
        scan_id = record_scan(make_integrity_result())
        alerts = generate_alerts(make_integrity_result(), suspicious, scan_id)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "medium")
        self.assertEqual(alerts[0]["category"], "suspicious_file")
        self.assertEqual(alerts[0]["file_path"], "script.js")

    def test_baseline_unavailable_critical_alert(self):
        """Scenario 7 + FR-09: baseline failure is CRITICAL, never clean."""
        integrity = make_integrity_result(status="baseline_unavailable")
        scan_id = record_scan(integrity)
        alerts = generate_alerts(integrity, make_suspicious_result(), scan_id)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["severity"], "critical")
        self.assertEqual(alert["category"], "baseline")
        self.assertEqual(
            alert["title"], "Baseline Unavailable or Authentication Failed"
        )
        self.assertIn("could not load or authenticate", alert["description"].lower())

    def test_invalid_directory_and_scan_error_alerts(self):
        """Scenario 8: system alerts for invalid directory and errors."""
        integrity = make_integrity_result(
            status="invalid_directory",
            errors=[{"path": "/nowhere",
                     "message": "Invalid or unavailable monitoring directory."}],
        )
        suspicious = make_suspicious_result(status="invalid_directory")
        scan_id = record_scan(integrity)
        alerts = generate_alerts(integrity, suspicious, scan_id)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["category"], "system")
        self.assertEqual(alerts[0]["severity"], "medium")

        # Errors from a completed scan also generate system alerts.
        integrity_errors = make_integrity_result(
            status="completed_with_errors",
            errors=[{"path": "/tmp/monitored/locked.txt",
                     "message": "Permission denied"}],
        )
        suspicious_errors = make_suspicious_result(
            status="completed_with_errors",
            errors=[{"path": "/tmp/monitored/other.txt",
                     "message": "stat failed"}],
        )
        scan_two = record_scan(integrity_errors)
        alerts_two = generate_alerts(integrity_errors, suspicious_errors, scan_two)
        self.assertEqual(len(alerts_two), 2)
        self.assertEqual({a["title"] for a in alerts_two},
                         {"Integrity Check Error", "Suspicious Detection Error"})
        self.assertTrue(all(a["category"] == "system" for a in alerts_two))

        # FR-10: findings and errors can coexist.
        integrity_both = make_integrity_result(
            status="completed_with_errors",
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}],
            errors=[{"path": "/tmp/monitored/locked.txt",
                     "message": "Permission denied"}],
        )
        scan_three = record_scan(integrity_both)
        alerts_three = generate_alerts(integrity_both, make_suspicious_result(), scan_three)
        self.assertEqual(
            {a["title"] for a in alerts_three},
            {"File Modified", "Integrity Check Error"},
        )

    def test_clean_scan_generates_no_alerts(self):
        """FR-16: a clean scan produces zero alerts."""
        scan_id = record_scan(make_integrity_result())
        alerts = generate_alerts(
            make_integrity_result(), make_suspicious_result(), scan_id
        )
        self.assertEqual(alerts, [])


class TestDeduplication(HashGuardTestCase):

    def test_overlapping_suspicious_arrays_single_alert(self):
        """FR-14: the same file in three arrays -> exactly one alert."""
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
        scan_id = record_scan(integrity)
        alerts = generate_alerts(integrity, suspicious, scan_id)

        # One integrity alert (added) + one suspicious alert, not three.
        self.assertEqual(len(alerts), 2)
        self.assertEqual(
            len([a for a in alerts if a["category"] == "suspicious_file"]), 1
        )

    def test_regenerating_alerts_creates_no_duplicates(self):
        """Scenario 10 / FR-14: generation is idempotent per scan."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}],
            deleted=[{"path": "b.txt", "baseline_hash": "3"}],
        )
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "bad.exe", "extension": ".exe",
                "reasons": ["File has a potentially risky extension."],
                "severity": "high",
            }],
        )
        scan_id = record_scan(integrity)

        first = generate_alerts(integrity, suspicious, scan_id)
        second = generate_alerts(integrity, suspicious, scan_id)
        third = generate_alerts(integrity, suspicious, scan_id)

        self.assertEqual(len(first), 3)
        self.assertEqual(len(second), 3)
        self.assertEqual(len(third), 3)
        self.assertEqual([a["alert_id"] for a in first],
                         [a["alert_id"] for a in second])

        # Direct database check: the uniqueness constraint holds.
        stored = get_alerts(scan_id=scan_id, limit=500)
        self.assertEqual(stored["total"], 3)

    def test_alerts_require_recorded_scan(self):
        """Alerts are foreign-keyed to scans: unknown ids are rejected."""
        with self.assertRaises(Exception):
            generate_alerts(make_integrity_result(), make_suspicious_result(), 999)


class TestStatusManagementAndFiltering(HashGuardTestCase):

    def _make_alerts(self):
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}],
            added=[{"path": "n.txt", "current_hash": "9"}],
        )
        suspicious = make_suspicious_result(
            suspicious_files=[{
                "path": "bad.exe", "extension": ".exe",
                "reasons": ["File has a potentially risky extension."],
                "severity": "high",
            }],
        )
        scan_id = record_scan(integrity)
        return generate_alerts(integrity, suspicious, scan_id)

    def test_update_alert_status_read_and_dismissed(self):
        """Scenario 9: status transitions."""
        alerts = self._make_alerts()
        alert_id = alerts[0]["alert_id"]

        updated = update_alert_status(alert_id, "read")
        self.assertEqual(updated["status"], "read")

        updated = update_alert_status(alert_id, "dismissed")
        self.assertEqual(updated["status"], "dismissed")

        back = update_alert_status(alert_id, "unread")
        self.assertEqual(back["status"], "unread")

        # Dismissed alerts remain stored (FR-13).
        dismissed = update_alert_status(alert_id, "dismissed")
        self.assertIsNotNone(get_alert_by_id(dismissed["alert_id"]))

    def test_update_alert_status_rejects_unsupported_values(self):
        alerts = self._make_alerts()
        for bad in ("deleted", "open", "", "READ", None):
            with self.assertRaises(ValueError):
                update_alert_status(alerts[0]["alert_id"], bad)

    def test_update_status_missing_alert_returns_none(self):
        self.assertIsNone(update_alert_status(99999, "read"))

    def test_filter_alerts(self):
        """FR-15: filter by severity, category, status and scan id."""
        self._make_alerts()

        high = get_alerts(severity="high")
        self.assertEqual(high["total"], 2)

        integrity_only = get_alerts(category="integrity")
        self.assertEqual(integrity_only["total"], 2)

        suspicious_only = get_alerts(category="suspicious_file")
        self.assertEqual(suspicious_only["total"], 1)

        unread = get_alerts(status="unread")
        self.assertEqual(unread["total"], 3)
        read = get_alerts(status="read")
        self.assertEqual(read["total"], 0)

        scan_one = get_alerts(scan_id=1)
        self.assertEqual(scan_one["total"], 3)

        combined = get_alerts(severity="high", category="integrity")
        self.assertEqual(combined["total"], 1)
        self.assertEqual(combined["items"][0]["title"], "File Modified")

    def test_alert_pagination(self):
        integrity = make_integrity_result(
            modified=[{"path": "f{}.txt".format(i),
                       "baseline_hash": "1", "current_hash": "2"}
                      for i in range(5)]
        )
        scan_id = record_scan(integrity)
        generate_alerts(integrity, make_suspicious_result(), scan_id)

        page_one = get_alerts(limit=3, offset=0)
        self.assertEqual(len(page_one["items"]), 3)
        self.assertEqual(page_one["total"], 5)

        page_two = get_alerts(limit=3, offset=3)
        self.assertEqual(len(page_two["items"]), 2)

    def test_alert_summary(self):
        self._make_alerts()
        update_alert_status(1, "read")
        summary = get_alert_summary()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["unread"], 2)
        self.assertEqual(summary["by_severity"]["high"], 2)
        self.assertEqual(summary["by_severity"]["medium"], 1)
        self.assertEqual(summary["by_status"]["read"], 1)

    def test_configurable_severities(self):
        """FR-08: severities are configurable, not hard-coded."""
        integrity = make_integrity_result(
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        scan_id = record_scan(integrity)

        set_severity_config({"file_modified": "low"})
        alerts = generate_alerts(integrity, make_suspicious_result(), scan_id)
        self.assertEqual(alerts[0]["severity"], "low")

        # Invalid overrides are rejected.
        with self.assertRaises(ValueError):
            set_severity_config({"file_modified": "extreme"})
        with self.assertRaises(ValueError):
            set_severity_config({"not_a_rule": "low"})

        reset_severity_config()
        integrity2 = make_integrity_result(
            modified=[{"path": "b.txt", "baseline_hash": "1", "current_hash": "2"}]
        )
        scan2 = record_scan(integrity2)
        alerts2 = generate_alerts(integrity2, make_suspicious_result(), scan2)
        self.assertEqual(alerts2[0]["severity"], "high")

    def test_alert_timestamp_uses_canonical_scan_time(self):
        integrity = make_integrity_result(
            scan_time="2026-11-07T12:00:00+05:00",
            modified=[{"path": "a.txt", "baseline_hash": "1", "current_hash": "2"}],
        )
        scan_id = record_scan(integrity)
        alerts = generate_alerts(
            integrity,
            make_suspicious_result(scan_time="2026-11-07T12:00:01+05:00"),
            scan_id,
        )
        self.assertEqual(alerts[0]["timestamp"], "2026-11-07T12:00:00+05:00")


class TestBaselineSeverityIsPinnedCritical(HashGuardTestCase):
    """Baseline verification failures must always stay CRITICAL (FR-09).

    The runtime severity configuration may tune other rules, but it can
    never lower (or otherwise change) the severity of a baseline
    verification / authentication failure.
    """

    def make_baseline_failure(self):
        integrity = make_integrity_result(
            status="baseline_unavailable",
            errors=[{
                "path": "/tmp/baseline.json",
                "message": "Baseline unavailable or authentication failed.",
            }],
        )
        scan_id = log_scan(integrity, make_suspicious_result())["scan_id"]
        return generate_alerts(integrity, make_suspicious_result(), scan_id)

    def test_lowering_the_baseline_severity_is_rejected(self):
        for forbidden in ("low", "medium", "high", "info"):
            with self.assertRaises(ValueError):
                set_severity_config(
                    {"baseline_unavailable": forbidden}
                )
        # nothing was changed:
        self.assertEqual(
            get_severity_config()["baseline_unavailable"], "critical"
        )

    def test_raising_or_reasserting_is_only_accepted_as_critical(self):
        # already critical: re-asserting the pinned value is accepted
        set_severity_config({"baseline_unavailable": "critical"})
        self.assertEqual(
            get_severity_config()["baseline_unavailable"], "critical"
        )

    def test_baseline_alert_stays_critical_despite_other_overrides(self):
        set_severity_config({
            "file_modified": "low",
            "suspicious_executable": "info",
        })
        alerts = self.make_baseline_failure()
        baseline_alerts = [
            a for a in alerts if a["dedupe_key"] == "baseline_unavailable"
        ]
        self.assertEqual(len(baseline_alerts), 1)
        self.assertEqual(baseline_alerts[0]["severity"], "critical")
        self.assertEqual(baseline_alerts[0]["category"], "baseline")

    def test_generation_enforces_the_pinned_floor(self):
        """Defense in depth: even a corrupted in-memory config cannot
        lower the severity actually used for the alert."""
        import alerts as alerts_module
        try:
            alerts_module._severity_config["baseline_unavailable"] = "low"
            alerts_list = self.make_baseline_failure()
            baseline_alerts = [
                a for a in alerts_list
                if a["dedupe_key"] == "baseline_unavailable"
            ]
            self.assertEqual(len(baseline_alerts), 1)
            self.assertEqual(baseline_alerts[0]["severity"], "critical")
        finally:
            reset_severity_config()


if __name__ == "__main__":
    unittest.main()
