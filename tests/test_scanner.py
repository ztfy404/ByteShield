import hashlib
import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from byteshield.scanner import Scanner, EICAR, CHUNK
from byteshield.report import make_report, save_report
from byteshield.cli import main


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.scanner = Scanner("builtin")

    def file(self, data, name="sample.txt"):
        path = self.root / name
        path.write_bytes(data)
        return path

    def test_regular_file_and_hash(self):
        path = self.file(b"ordinary document")
        result = self.scanner.scan_file(path)
        self.assertEqual(result.status, "no_match")
        self.assertEqual(result.sha256, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_eicar_is_detected_without_deleting(self):
        path = self.file(EICAR)
        self.assertEqual(self.scanner.scan_file(path).status, "detected")
        self.assertEqual(path.read_bytes(), EICAR)

    def test_eicar_crosses_read_boundary(self):
        result = self.scanner.scan_file(self.file(b"." * (CHUNK - 10) + EICAR + b"tail"))
        self.assertEqual(result.status, "detected")

    def test_empty_file(self):
        self.assertEqual(self.scanner.scan_file(self.file(b"")).status, "no_match")

    def test_unicode_paths_and_deduplication(self):
        path = self.file(b"text", "проверка файла.txt")
        results = list(self.scanner.scan([self.root, path]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "no_match")

    def test_missing_is_error(self):
        self.assertEqual(self.scanner.scan_file(self.root / "missing").status, "error")

    def test_large_file_is_skipped(self):
        result = Scanner("builtin", max_size_mb=0.001).scan_file(self.file(b"." * 2048))
        self.assertEqual(result.status, "skipped")

    def test_cancelled_scan(self):
        event = threading.Event()
        event.set()
        self.assertEqual(list(self.scanner.scan([self.root], event)), [])

    def test_symlinks_are_not_followed(self):
        path = self.file(EICAR)
        link = self.root / "link"
        try:
            link.symlink_to(path)
        except OSError:
            self.skipTest("Symlinks unavailable")
        self.assertEqual(self.scanner.scan_file(link).status, "skipped")

    def test_quarantine_is_excluded(self):
        quarantine = self.root / "quarantine"
        quarantine.mkdir()
        (quarantine / "sample.bin").write_bytes(EICAR)
        self.file(b"normal")
        results = list(Scanner("builtin", quarantine_dir=quarantine).scan([self.root]))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "no_match")

    def test_custom_signature(self):
        path = self.file(b"synthetic test document")
        database = self.root / "db.json"
        database.write_text(json.dumps({"version": 1, "sha256": {hashlib.sha256(path.read_bytes()).hexdigest(): "Demo.Hash"}}))
        result = Scanner("builtin", signatures=database).scan_file(path)
        self.assertEqual((result.status, result.threat), ("detected", "Demo.Hash"))

    def test_invalid_database_is_rejected(self):
        database = self.root / "db.json"
        database.write_text('{"version":1,"sha256":{"bad":"name"}}')
        with self.assertRaises(ValueError):
            Scanner("builtin", signatures=database)

    def test_required_clamav_cannot_silently_fall_back(self):
        with patch("byteshield.scanner.shutil.which", return_value=None):
            with self.assertRaises(ValueError):
                Scanner("clamav")

    def test_auto_fallback_is_explicit(self):
        with patch("byteshield.scanner.shutil.which", return_value=None):
            scanner = Scanner("auto")
            self.assertEqual(scanner.engine, "builtin")
            self.assertIn("Тестовая", scanner.description)

    def clamav_result(self, returncode, stdout="", stderr=""):
        path = self.file(b"normal")
        with patch("byteshield.scanner.shutil.which", return_value="/example/clamscan"):
            scanner = Scanner("clamav")
        command = subprocess.CompletedProcess([], returncode, stdout, stderr)
        with patch("byteshield.scanner.subprocess.run", return_value=command):
            return scanner.scan_file(path)

    def test_clamav_detection(self):
        result = self.clamav_result(1, "sample.txt: Demo.Signature FOUND\n")
        self.assertEqual((result.status, result.threat), ("detected", "Demo.Signature"))

    def test_clamav_error_is_not_a_clean_result(self):
        result = self.clamav_result(2, stderr="Database missing")
        self.assertEqual(result.status, "error")
        self.assertIn("Database missing", result.detail)

    def test_clamav_malformed_detection_is_error(self):
        self.assertEqual(self.clamav_result(1, "invalid output").status, "error")

    def test_clamav_timeout_is_error(self):
        with patch("byteshield.scanner.shutil.which", return_value="/example/clamscan"):
            scanner = Scanner("clamav")
        with patch("byteshield.scanner.subprocess.run", side_effect=subprocess.TimeoutExpired("clamscan", 60)):
            self.assertEqual(scanner.scan_file(self.file(b"normal")).status, "error")

    def test_report_contains_errors_and_skips(self):
        path = self.file(b"text")
        results = list(self.scanner.scan([path, self.root / "absent"]))
        report = make_report(results, "builtin", cancelled=True)
        out = self.root / "report.json"
        save_report(out, report)
        saved = json.loads(out.read_text())
        self.assertEqual(saved["counts"], {"no_match": 1, "error": 1})
        self.assertTrue(saved["cancelled"])

    def test_cli_detection_exit_code_and_report(self):
        report = self.root / "result.json"
        self.assertEqual(main(["scan", str(self.file(EICAR)), "--engine", "builtin", "--report", str(report)]), 1)
        self.assertEqual(json.loads(report.read_text())["counts"]["detected"], 1)

    def test_cli_invalid_size(self):
        self.assertEqual(main(["scan", str(self.root), "--max-size-mb", "0"]), 2)
