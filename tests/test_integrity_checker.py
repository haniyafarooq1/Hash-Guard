
import unittest
import tempfile
import json

from pathlib import Path
from baseline import create_baseline
from integrity_checker import check_integrity

class TestIntegrityChecker(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.monitored_folder = self.root / "monitored"
        self.monitored_folder.mkdir()

        self.baseline_file = self.root / "baseline.json"

        (self.monitored_folder / "hello.txt").write_text("Hello Hash Guard!", encoding="utf-8")
        (self.monitored_folder / "notes.txt").write_text("Original notes.", encoding="utf-8")

        self.create_test_baseline()

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_test_baseline(self):
        result = create_baseline(str(self.monitored_folder), str(self.baseline_file))
        self.assertTrue(result)

    def scan(self):
        return check_integrity(str(self.monitored_folder), str(self.baseline_file))

    def test_no_changes(self):
        result = self.scan()

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["summary"]["modified"], 0)
        self.assertEqual(result["summary"]["added"], 0)
        self.assertEqual(result["summary"]["deleted"], 0)
        self.assertEqual(result["summary"]["renamed"], 0)

    def test_modified_file(self):

        (self.monitored_folder / "hello.txt").write_text("Modified content.", encoding="utf-8")
        result = self.scan()

        self.assertEqual(result["summary"]["modified"], 1)
        self.assertEqual(result["modified"][0]["path"], "hello.txt")

    def test_added_file(self):

        (self.monitored_folder / "new.txt").write_text("New file.", encoding="utf-8")

        result = self.scan()
        self.assertEqual(result["summary"]["added"], 1)
        self.assertEqual(result["added"][0]["path"], "new.txt")

    def test_deleted_file(self):

        (self.monitored_folder / "notes.txt").unlink()

        result = self.scan()
        self.assertEqual(result["summary"]["deleted"], 1)
        self.assertEqual(result["deleted"][0]["path"], "notes.txt")

    def test_renamed_file(self):

        old_path = self.monitored_folder / "notes.txt"
        new_path = self.monitored_folder / "renamed_notes.txt"

        old_path.rename(new_path)

        result = self.scan()

        self.assertEqual(result["summary"]["renamed"], 1)
        self.assertEqual(result["renamed"][0]["old_path"], "notes.txt")
        self.assertEqual(result["renamed"][0]["new_path"], "renamed_notes.txt")
        self.assertEqual(result["summary"]["added"], 0)
        self.assertEqual(result["summary"]["deleted"], 0)

    def test_multiple_changes(self):

        (self.monitored_folder / "hello.txt").write_text("Changed hello.", encoding="utf-8")
        (self.monitored_folder / "new.txt").write_text("New content.", encoding="utf-8")
        (self.monitored_folder / "notes.txt").unlink()

        result = self.scan()

        self.assertEqual(result["summary"]["modified"], 1)
        self.assertEqual(result["summary"]["added"], 1)
        self.assertEqual(result["summary"]["deleted"], 1)

    def test_invalid_directory(self):

        invalid_folder = self.root / "does_not_exist"
        result = check_integrity(str(invalid_folder), str(self.baseline_file))

        self.assertEqual(result["status"], "invalid_directory")

    def test_missing_baseline(self):

        missing_baseline = self.root / "missing.json"
        result = check_integrity(str(self.monitored_folder), str(missing_baseline))
        self.assertEqual(result["status"], "baseline_unavailable")

    def test_missing_signature(self):

        signature_file = Path(str(self.baseline_file) + ".sig")
        signature_file.unlink()
        result = self.scan()
        self.assertEqual(result["status"], "baseline_unavailable")

    def test_tampered_baseline(self):

        with open(self.baseline_file, "r", encoding="utf-8") as file:
            baseline = json.load(file)

        baseline["hello.txt"] = "0" * 64

        with open(self.baseline_file, "w", encoding="utf-8") as file:
            json.dump(baseline, file, indent=4)

        result = self.scan()
        self.assertEqual(result["status"], "baseline_unavailable")


if __name__ == "__main__":
    unittest.main()
