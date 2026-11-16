import hashlib
import tempfile
import unittest
from pathlib import Path
from byteshield.quarantine import Quarantine


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "sample.txt"
        self.data = b"synthetic harmless data"
        self.path.write_bytes(self.data)
        self.digest = hashlib.sha256(self.data).hexdigest()
        self.store = Quarantine(self.root / "store")

    def test_round_trip(self):
        record = self.store.add(self.path, self.digest)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.store.items()[0]["id"], record["id"])
        dest = self.root / "restored.txt"
        self.store.restore(record["id"], dest)
        self.assertEqual(dest.read_bytes(), self.data)
        self.assertTrue((self.store.directory / (record["id"] + ".bin")).exists())

    def test_restore_does_not_overwrite(self):
        record = self.store.add(self.path, self.digest)
        dest = self.root / "exists.txt"
        dest.write_text("keep")
        with self.assertRaises(FileExistsError):
            self.store.restore(record["id"], dest)
        self.assertEqual(dest.read_text(), "keep")

    def test_changed_source_is_not_removed(self):
        self.path.write_bytes(b"modified")
        with self.assertRaises(ValueError):
            self.store.add(self.path, self.digest)
        self.assertTrue(self.path.exists())
        self.assertEqual(list(self.store.directory.iterdir()), [])

    def test_tampered_blob_is_not_restored(self):
        record = self.store.add(self.path, self.digest)
        (self.store.directory / (record["id"] + ".bin")).write_bytes(b"tampered")
        dest = self.root / "result.txt"
        with self.assertRaises(ValueError):
            self.store.restore(record["id"], dest)
        self.assertFalse(dest.exists())

    def test_path_traversal_id_is_rejected(self):
        with self.assertRaises(ValueError):
            self.store.restore("../../anything", self.root / "result")

    def test_restore_inside_quarantine_is_rejected(self):
        record = self.store.add(self.path, self.digest)
        with self.assertRaises(ValueError):
            self.store.restore(record["id"], self.store.directory / "other.bin")

    def test_symlink_source_is_rejected(self):
        link = self.root / "link"
        try:
            link.symlink_to(self.path)
        except OSError:
            self.skipTest("Symlinks unavailable")
        with self.assertRaises(ValueError):
            self.store.add(link, self.digest)
        self.assertTrue(self.path.exists())

    def test_empty_quarantine(self):
        self.assertEqual(self.store.items(), [])
