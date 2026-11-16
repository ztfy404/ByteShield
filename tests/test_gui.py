import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


@unittest.skipUnless(os.environ.get("DISPLAY"), "GUI test needs an X display")
class GuiTests(unittest.TestCase):
    def test_scan_quarantine_and_restore(self):
        import tkinter as tk
        from byteshield.gui import App
        from byteshield.quarantine import Quarantine
        from byteshield.scanner import EICAR
        root = tk.Tk()
        self.addCleanup(root.destroy)
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            sample = folder / "test-file.txt"
            sample.write_bytes(EICAR)
            (folder / "document.txt").write_text("Обычный документ", encoding="utf-8")
            app = App(root)
            app.storage = Quarantine(folder / "quarantine")
            app.targets = [folder]
            app.engine.set("builtin")
            app.scan()
            deadline = time.monotonic() + 5
            while app.busy and time.monotonic() < deadline:
                root.update()
                time.sleep(0.01)
            self.assertFalse(app.busy)
            self.assertEqual(len(app.results), 2)
            detected = next(k for k, v in app.row_results.items() if v.status == "detected")
            app.table.selection_set(detected)
            with patch("byteshield.gui.messagebox.askyesno", return_value=True):
                app.quarantine_selected()
            self.assertFalse(sample.exists())
            identifier = app.qtable.get_children()[0]
            app.qtable.selection_set(identifier)
            restored = folder / "restored.txt"
            with patch("byteshield.gui.filedialog.asksaveasfilename", return_value=str(restored)), patch("byteshield.gui.messagebox.showinfo"):
                app.restore_selected()
            self.assertEqual(restored.read_bytes(), EICAR)
            report = folder / "result.json"
            with patch("byteshield.gui.filedialog.asksaveasfilename", return_value=str(report)):
                app.export_report()
            self.assertTrue(report.exists())
