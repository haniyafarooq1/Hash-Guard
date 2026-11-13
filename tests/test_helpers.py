"""Shared helpers for the Hash Guard test suite.

Provides builders for synthetic integrity / suspicious result
dictionaries that match the exact structures returned by the real
detection modules, plus a base class that isolates every test
against a temporary SQLite database.
"""

import tempfile
import unittest
from pathlib import Path

from alerts import reset_severity_config
from backend.storage import database


def make_integrity_result(
    status="success",
    scan_time="2026-11-07T12:00:00+05:00",
    directory="/tmp/monitored",
    summary=None,
    modified=None,
    added=None,
    deleted=None,
    renamed=None,
    errors=None,
):
    """Build an integrity result shaped exactly like check_integrity()'s."""
    modified = modified or []
    added = added or []
    deleted = deleted or []
    renamed = renamed or []
    errors = errors or []
    return {
        "status": status,
        "scan_time": scan_time,
        "directory": directory,
        "summary": summary or {
            "modified": len(modified),
            "added": len(added),
            "deleted": len(deleted),
            "renamed": len(renamed),
            "errors": len(errors),
        },
        "modified": modified,
        "added": added,
        "deleted": deleted,
        "renamed": renamed,
        "errors": errors,
    }


def make_suspicious_result(
    status="success",
    scan_time="2026-11-07T12:00:01+05:00",
    directory="/tmp/monitored",
    summary=None,
    suspicious_files=None,
    newly_added_files=None,
    executable_files=None,
    errors=None,
):
    """Build a suspicious result shaped like check_suspicious_files()'s."""
    suspicious_files = suspicious_files or []
    newly_added_files = newly_added_files or []
    executable_files = executable_files or []
    errors = errors or []
    return {
        "status": status,
        "scan_time": scan_time,
        "directory": directory,
        "summary": summary or {
            "suspicious_files": len(suspicious_files),
            "newly_added_files": len(newly_added_files),
            "executable_files": len(executable_files),
            "errors": len(errors),
        },
        "suspicious_files": suspicious_files,
        "newly_added_files": newly_added_files,
        "executable_files": executable_files,
        "errors": errors,
    }


class HashGuardTestCase(unittest.TestCase):
    """Base class: temporary database + clean severity config per test."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_file = self.root / "test.db"
        database.set_database_path(str(self.db_file))
        database.init_db()
        reset_severity_config()

    def tearDown(self):
        database.reset_connections()
        database.set_database_path(None)
        database.reset_connections()
        reset_severity_config()
        self.temp_dir.cleanup()
