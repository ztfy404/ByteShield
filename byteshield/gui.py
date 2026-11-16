"""Окно ByteShield. Сканирование выполняется в отдельном потоке."""
import queue
from collections import Counter
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk, font
from . import __version__
from .paths import data_dir
from .quarantine import Quarantine
from .report import make_report, save_report
from .scanner import Scanner

STATUS = {"detected": "Обнаружено", "no_match": "Совпадений нет", "error": "Ошибка", "skipped": "Пропущено"}


class App:
    def __init__(self, root):
        self.root = root
        self.targets, self.results, self.row_results = [], [], {}
        self.counts = Counter()
        self.events, self.cancel = queue.Queue(), threading.Event()
        self.busy, self.engine_description = False, ""
        self.storage = Quarantine(data_dir() / "quarantine")
        root.title(f"ByteShield {__version__}")
        root.geometry("1050x700")
        root.minsize(830, 570)
        root.configure(bg="#eef3f8")
        families = {name.lower() for name in font.families(root)}
        family = next((name for name in ("Segoe UI", "DejaVu Sans", "Noto Sans", "Liberation Sans", "Arial") if name.lower() in families), font.nametofont("TkDefaultFont").actual("family"))
        font.nametofont("TkDefaultFont").configure(family=family, size=10)
        style = ttk.Style(root)
        style.theme_use("clam")
        style.configure("TFrame", background="#eef3f8")
        style.configure("TLabel", background="#eef3f8", foreground="#18324b", font=(family, 10))
        style.configure("Title.TLabel", font=(family, 25, "bold"))
        style.configure("TButton", padding=(12, 8), font=(family, 10))
        style.configure("Accent.TButton", background="#225bd6", foreground="white")
        style.map("Accent.TButton", background=[("active", "#1748b0"), ("disabled", "#a3b9e5")])
        style.configure("TNotebook.Tab", padding=(14, 7), font=(family, 10))
        style.configure("Treeview", rowheight=28, font=(family, 10))
        style.configure("Treeview.Heading", font=(family, 10, "bold"))
        content = ttk.Frame(root, padding=24)
        content.pack(fill="both", expand=True)
        ttk.Label(content, text="ByteShield", style="Title.TLabel").pack(anchor="w")
        ttk.Label(content, text="Проверка файлов и папок по запросу").pack(anchor="w", pady=(0, 12))
        controls = ttk.Frame(content)
        controls.pack(fill="x")
        self.pick_files = ttk.Button(controls, text="Выбрать файлы", command=self.choose_files)
        self.pick_files.pack(side="left")
        self.pick_folder = ttk.Button(controls, text="Выбрать папку", command=self.choose_folder)
        self.pick_folder.pack(side="left", padx=8)
        ttk.Label(controls, text="Движок:").pack(side="left", padx=(12, 5))
        self.engine = ttk.Combobox(controls, values=["auto", "builtin", "clamav"], state="readonly", width=10)
        self.engine.set("auto")
        self.engine.pack(side="left")
        self.start = ttk.Button(controls, text="Проверить", command=self.scan, style="Accent.TButton")
        self.start.pack(side="right")
        self.stop = ttk.Button(controls, text="Отмена", command=self.cancel.set, state="disabled")
        self.stop.pack(side="right", padx=8)
        self.selection = ttk.Label(content, text="Выберите файлы или папку", wraplength=950)
        self.selection.pack(anchor="w", pady=10)
        self.mode = ttk.Label(content, text=Scanner(quarantine_dir=self.storage.directory).description)
        self.mode.pack(anchor="w", pady=(0, 8))
        notebook = ttk.Notebook(content)
        notebook.pack(fill="both", expand=True)
        checks = ttk.Frame(notebook, padding=8)
        quarantine = ttk.Frame(notebook, padding=8)
        notebook.add(checks, text="Проверка")
        notebook.add(quarantine, text="Карантин")
        self.table = self.make_table(checks, ("status", "path", "threat"), ("Результат", "Файл", "Обнаружение / подробности"))
        self.table.tag_configure("detected", foreground="#a51c30", background="#fff0f2")
        self.table.tag_configure("error", foreground="#98610b")
        actions = ttk.Frame(checks)
        actions.pack(fill="x", pady=(8, 0))
        self.quarantine_button = ttk.Button(actions, text="В карантин", command=self.quarantine_selected)
        self.quarantine_button.pack(side="left")
        self.export = ttk.Button(actions, text="Сохранить JSON-отчёт", command=self.export_report)
        self.export.pack(side="right")
        self.qtable = self.make_table(quarantine, ("id", "path", "date"), ("ID", "Исходный файл", "Дата"))
        qactions = ttk.Frame(quarantine)
        qactions.pack(fill="x", pady=(8, 0))
        ttk.Button(qactions, text="Обновить", command=self.refresh_quarantine).pack(side="left")
        ttk.Button(qactions, text="Восстановить копию…", command=self.restore_selected).pack(side="right")
        ttk.Label(quarantine, text="Копии хранятся локально. Восстанавливайте только файлы, которым доверяете.", wraplength=900).pack(anchor="w", pady=8)
        self.progress = ttk.Progressbar(content, mode="indeterminate")
        self.progress.pack(side="bottom", fill="x", pady=(12, 6), before=notebook)
        self.status = ttk.Label(content, text="Готов к проверке")
        self.status.pack(side="bottom", anchor="w", before=self.progress)
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.refresh_quarantine()
        root.after(100, self.poll)

    @staticmethod
    def make_table(parent, columns, headings):
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True)
        table = ttk.Treeview(frame, columns=columns, show="headings", selectmode="browse")
        for index, (column, heading) in enumerate(zip(columns, headings)):
            table.heading(column, text=heading)
            table.column(column, width=135 if index == 0 else 340, minwidth=100, stretch=True)
        scroll = ttk.Scrollbar(frame, orient="vertical", command=table.yview)
        table.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        table.pack(fill="both", expand=True)
        return table

    def choose_files(self):
        paths = filedialog.askopenfilenames(title="Файлы для проверки")
        if paths:
            self.targets = list(paths)
            self.selection.configure(text="; ".join(self.targets))

    def choose_folder(self):
        path = filedialog.askdirectory(title="Папка для проверки")
        if path:
            self.targets = [path]
            self.selection.configure(text=path)

    def scan(self):
        if not self.targets:
            messagebox.showinfo("ByteShield", "Сначала выберите файлы или папку")
            return
        try:
            scanner = Scanner(self.engine.get(), quarantine_dir=self.storage.directory)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Движок недоступен", str(exc))
            return
        self.results, self.row_results = [], {}
        self.counts = Counter()
        self.table.delete(*self.table.get_children())
        self.cancel.clear()
        self.busy = True
        self.engine_description = scanner.description
        self.mode.configure(text=scanner.description)
        self.engine.configure(state="disabled")
        for button in [self.start, self.pick_files, self.pick_folder, self.quarantine_button, self.export]:
            button.configure(state="disabled")
        self.stop.configure(state="normal")
        self.progress.start(12)
        self.status.configure(text="Проверка…")
        targets = self.targets[:]
        def worker():
            try:
                for result in scanner.scan(targets, self.cancel):
                    self.events.put(("result", result))
            except Exception as exc:
                self.events.put(("error", str(exc)))
            finally:
                self.events.put(("done", None))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        for _ in range(200):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "result":
                self.results.append(value)
                self.counts[value.status] += 1
                item = self.table.insert("", "end", values=(STATUS[value.status], value.path, value.threat or value.detail), tags=(value.status,))
                self.row_results[item] = value
                self.update_counts("Проверка")
            elif kind == "error":
                messagebox.showerror("Ошибка проверки", value)
            elif kind == "done":
                self.busy = False
                self.progress.stop()
                self.stop.configure(state="disabled")
                self.engine.configure(state="readonly")
                for button in [self.start, self.pick_files, self.pick_folder, self.quarantine_button, self.export]:
                    button.configure(state="normal")
                self.update_counts("Остановлено" if self.cancel.is_set() else "Готово")
        self.root.after(100, self.poll)

    def update_counts(self, prefix):
        detected = self.counts["detected"]
        errors = self.counts["error"]
        skipped = self.counts["skipped"]
        self.status.configure(text=f"{prefix} · файлов: {len(self.results)} · обнаружено: {detected} · ошибок: {errors} · пропущено: {skipped}")

    def quarantine_selected(self):
        selected = self.table.selection()
        if not selected:
            return
        result = self.row_results[selected[0]]
        if result.status != "detected":
            messagebox.showinfo("ByteShield", "Выберите файл с результатом «Обнаружено»")
            return
        if not messagebox.askyesno("Перенос в карантин", f"Перенести файл в карантин?\n{result.path}\nИсходный файл будет удалён после проверки копии."):
            return
        try:
            self.storage.add(result.path, result.sha256)
            self.table.set(selected[0], "threat", result.threat + " — в карантине")
            self.refresh_quarantine()
        except (OSError, ValueError) as exc:
            messagebox.showerror("Карантин", str(exc))

    def refresh_quarantine(self):
        self.qtable.delete(*self.qtable.get_children())
        try:
            for record in self.storage.items():
                self.qtable.insert("", "end", iid=record["id"], values=(record["id"], record["original_path"], record["created_at"]))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Не удалось прочитать карантин", str(exc))

    def restore_selected(self):
        selected = self.qtable.selection()
        if not selected:
            return
        name = Path(self.qtable.item(selected[0], "values")[1]).name
        target = filedialog.asksaveasfilename(title="Восстановить копию в новый файл", initialfile=name)
        if not target:
            return
        try:
            self.storage.restore(selected[0], target)
            messagebox.showinfo("ByteShield", "Копия восстановлена. Файл в карантине сохранён.")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Восстановление", str(exc))

    def export_report(self):
        if not self.results:
            messagebox.showinfo("ByteShield", "Сначала выполните проверку")
            return
        target = filedialog.asksaveasfilename(title="Сохранить отчёт", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if target:
            try:
                save_report(target, make_report(self.results, self.engine_description, self.cancel.is_set()))
            except (OSError, ValueError) as exc:
                messagebox.showerror("Отчёт", str(exc))

    def close(self):
        self.cancel.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
