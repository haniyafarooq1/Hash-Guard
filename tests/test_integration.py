
import tempfile
import unittest
from pathlib import Path
from baseline import create_baseline
from integrity_checker import check_integrity
from suspicious_detector import check_suspicious_files

class TestIntegration(unittest.TestCase):

    def test_new_suspicious_file_detected_by_both_modules(self):

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            monitored_folder = root / "Important_Files"
            monitored_folder.mkdir()

            baseline_file = root / "baseline.json"
            (monitored_folder / "notes.txt").write_text("Original document")

            baseline_created = create_baseline(str(monitored_folder), str(baseline_file))
            self.assertTrue(baseline_created)

            (monitored_folder / "unexpected.exe").write_text("Harmless dummy file for testing")
            integrity_result = check_integrity(str(monitored_folder), str(baseline_file))

            self.assertEqual(integrity_result["status"], "success")
            self.assertEqual(integrity_result["summary"]["added"], 1)

            suspicious_result = check_suspicious_files(str(monitored_folder), integrity_result)

            self.assertEqual(suspicious_result["status"], "success")
            self.assertEqual(suspicious_result["summary"]["newly_added_files"], 1)
            self.assertEqual(suspicious_result["summary"]["suspicious_files"], 1)
            self.assertEqual(suspicious_result["suspicious_files"][0]["path"], "unexpected.exe")


if __name__ == "__main__":
    unittest.main()
