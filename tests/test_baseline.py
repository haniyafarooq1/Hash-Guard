
import unittest
import tempfile
import hashlib
from pathlib import Path
from baseline import (calculate_hash, build_baseline, create_baseline, load_baseline)


class TestBaseline(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp_dir.name) / "test_files"
        self.folder.mkdir()

        self.baseline_file = Path(self.temp_dir.name) / "baseline.json"
        (self.folder / "hello.txt").write_text("Hello Hash Guard!", encoding="utf-8")
        (self.folder / "notes.txt").write_text("Testing file integrity.", encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_sha256_hash(self):
        file_path = self.folder / "hello.txt"

        expected = hashlib.sha256(b"Hello Hash Guard!").hexdigest()
        self.assertEqual(calculate_hash(file_path), expected)

    def test_build_baseline(self):
        baseline = build_baseline(str(self.folder))

        self.assertEqual(len(baseline), 2)
        self.assertIn("hello.txt", baseline)
        self.assertIn("notes.txt", baseline)

    def test_create_and_load_baseline(self):
        result = create_baseline(str(self.folder), str(self.baseline_file))

        self.assertTrue(result)
        baseline = load_baseline(str(self.baseline_file))
        self.assertEqual(len(baseline), 2)

    def test_tampered_baseline_rejected(self):
        create_baseline(str(self.folder), str(self.baseline_file))

        with open(self.baseline_file, "a", encoding="utf-8") as file:
            file.write(" ")

        baseline = load_baseline(str(self.baseline_file))
        self.assertEqual(baseline, {})

    def test_invalid_folder(self):
        result = create_baseline(str(self.folder / "does_not_exist"), str(self.baseline_file))
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
