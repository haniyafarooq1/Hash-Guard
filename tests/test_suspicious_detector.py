
import os
import tempfile
import unittest
from pathlib import Path
from suspicious_detector import check_suspicious_files

class TestSuspiciousDetector(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_file(self, filename, content="sample content"):
        file_path = self.folder / filename
        file_path.write_text(content)
        return file_path

    def test_ordinary_file_not_suspicious(self):
        self.create_file("notes.txt")

        result = check_suspicious_files(self.folder)

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["summary"]["suspicious_files"], 0)
        self.assertEqual(result["suspicious_files"], [])

    def test_exe_file_flagged(self):
        self.create_file("program.exe")

        result = check_suspicious_files(self.folder)

        self.assertEqual(result["summary"]["suspicious_files"], 1)
        self.assertEqual(result["summary"]["executable_files"], 1)
        self.assertEqual(result["suspicious_files"][0]["path"], "program.exe")

    def test_bat_and_ps1_files_flagged(self):
        self.create_file("script.bat")
        self.create_file("script.ps1")

        result = check_suspicious_files(self.folder)

        self.assertEqual(result["summary"]["suspicious_files"], 2)
        self.assertEqual(result["summary"]["executable_files"], 2)

    def test_newly_added_file_detected(self):
        self.create_file("new_file.txt")

        integrity_result = { "added": [{"path": "new_file.txt", "current_hash": "sample_hash"}]}
        result = check_suspicious_files(self.folder, integrity_result)

        self.assertEqual(result["summary"]["newly_added_files"], 1)
        self.assertEqual(result["newly_added_files"][0]["path"], "new_file.txt")
        self.assertEqual(result["summary"]["suspicious_files"], 1)

    def test_executable_permission_detected(self):
        file_path = self.create_file("script.sh")

        try:
            os.chmod(file_path, 0o755)
            result = check_suspicious_files(self.folder)
            self.assertEqual(result["summary"]["executable_files"], 1)

        except OSError:
            self.skipTest("Executable permissions are unavailable.")

    def test_invalid_directory(self):
        invalid_folder = self.folder / "missing_folder"
        result = check_suspicious_files(invalid_folder)

        self.assertEqual(result["status"], "invalid_directory")
        self.assertEqual(result["summary"]["errors"], 1)

    def test_multiple_suspicious_files(self):
        self.create_file("program.exe")
        self.create_file("script.bat")
        self.create_file("notes.txt")

        result = check_suspicious_files(self.folder)

        self.assertEqual(result["summary"]["suspicious_files"], 2)
        self.assertEqual(result["summary"]["executable_files"], 2)

    def test_case_insensitive_extensions(self):
        self.create_file("PROGRAM.EXE")

        result = check_suspicious_files(self.folder)
        self.assertEqual(result["summary"]["suspicious_files"], 1)


if __name__ == "__main__":
    unittest.main()

