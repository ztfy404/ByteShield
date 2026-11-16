"""Чтение файлов без запуска. SHA-256, EICAR и необязательный ClamAV."""
from __future__ import annotations
import hashlib
import json
import os
import shutil
import stat
import subprocess
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator
from .paths import inside

# Безопасная тестовая строка EICAR, не вредоносная программа.
EICAR = (b"X5O!P%@AP[4" + bytes([92]) + b"PZX54(P^)7CC)7}"
         + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
CHUNK = 64 * 1024


@dataclass
class ScanResult:
    path: str
    status: str  # detected / no_match / error / skipped
    sha256: str = ""
    threat: str = ""
    detail: str = ""
    size: int = 0
    engine: str = "builtin"

    def to_dict(self) -> dict:
        return asdict(self)


def signatures_from(path: Path | None = None) -> dict[str, str]:
    source = path or Path(__file__).parent / "data" / "signatures.json"
    with source.open(encoding="utf-8") as f:
        doc = json.load(f)
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError("Неверный формат базы сигнатур")
    signatures = doc.get("sha256")
    if not isinstance(signatures, dict):
        raise ValueError("В базе требуется объект sha256")
    result = {}
    for digest, name in signatures.items():
        if (not isinstance(digest, str) or len(digest) != 64
                or any(c not in "0123456789abcdefABCDEF" for c in digest)
                or not isinstance(name, str) or not name.strip()):
            raise ValueError("Неверная SHA-256 сигнатура или название")
        result[digest.lower()] = name.strip()
    return result


class Scanner:
    def __init__(self, engine="auto", signatures=None, max_size_mb=128,
                 quarantine_dir: Path | None = None, timeout=60):
        if engine not in ("auto", "builtin", "clamav"):
            raise ValueError("Неизвестный движок")
        if max_size_mb <= 0 or timeout <= 0:
            raise ValueError("Лимит размера и таймаут должны быть положительными")
        self.clamscan = shutil.which("clamscan") if engine != "builtin" else None
        if engine == "clamav" and not self.clamscan:
            raise ValueError("clamscan не найден. Установите ClamAV или выберите builtin")
        self.engine = "clamav" if self.clamscan else "builtin"
        self.signatures = signatures_from(Path(signatures) if signatures else None)
        self.max_bytes = int(max_size_mb * 1024 * 1024)
        self.timeout = timeout
        self.quarantine_dir = quarantine_dir

    @property
    def description(self):
        if self.engine == "clamav":
            return "ClamAV + локальные сигнатуры"
        return "Тестовая база: EICAR и SHA-256 (ClamAV не используется)"

    def scan_file(self, path: Path, cancel: threading.Event | None = None) -> ScanResult:
        path = Path(os.path.abspath(path))
        result = ScanResult(str(path), "error", engine=self.engine)
        try:
            if self.quarantine_dir and inside(path, self.quarantine_dir):
                result.status, result.detail = "skipped", "Каталог карантина"
                return result
            before = path.lstat()
            if not stat.S_ISREG(before.st_mode):
                result.status, result.detail = "skipped", "Ссылка или не обычный файл"
                return result
            result.size = before.st_size
            if before.st_size > self.max_bytes:
                result.status, result.detail = "skipped", "Превышен лимит размера"
                return result
            digest, tail, eicar, total = hashlib.sha256(), b"", False, 0
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as f:
                opened = os.fstat(f.fileno())
                if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                    raise OSError("Файл изменился до открытия")
                while True:
                    if cancel and cancel.is_set():
                        result.status, result.detail = "skipped", "Проверка отменена"
                        return result
                    block = f.read(CHUNK)
                    if not block:
                        break
                    total += len(block)
                    if total > self.max_bytes:
                        result.status, result.detail = "skipped", "Файл вырос выше лимита"
                        return result
                    digest.update(block)
                    joined = tail + block
                    eicar = eicar or EICAR in joined
                    tail = joined[-(len(EICAR) - 1):]
                after = os.fstat(f.fileno())
            current = path.lstat()
            fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
            if fingerprint(before) != fingerprint(after) or fingerprint(before) != fingerprint(current):
                raise OSError("Файл изменился во время проверки; повторите сканирование")
            result.sha256 = digest.hexdigest()
            result.threat = self.signatures.get(result.sha256, "")
            if eicar:
                result.threat = "EICAR-Test-File (безопасный тест)"
            if result.threat:
                result.status = "detected"
                return result
            if self.engine == "clamav":
                if cancel and cancel.is_set():
                    result.status, result.detail = "skipped", "Проверка отменена"
                    return result
                command = subprocess.run(
                    [self.clamscan, "--no-summary", "--stdout", "--", str(path)],
                    capture_output=True, text=True, errors="replace", timeout=self.timeout,
                    shell=False)
                if fingerprint(path.lstat()) != fingerprint(before):
                    raise OSError("Файл изменился во время проверки ClamAV")
                if command.returncode == 1:
                    found = [s for s in command.stdout.splitlines() if s.endswith(" FOUND")]
                    if not found:
                        raise OSError("ClamAV вернул обнаружение без имени угрозы")
                    result.status = "detected"
                    result.threat = found[-1].rsplit(": ", 1)[-1].removesuffix(" FOUND")
                    return result
                if command.returncode != 0:
                    raise OSError((command.stderr or command.stdout or "Ошибка ClamAV").strip()[:500])
            result.status = "no_match"
        except subprocess.TimeoutExpired:
            result.detail = "ClamAV превысил время проверки"
        except (OSError, ValueError) as exc:
            result.detail = str(exc)
        return result

    def scan(self, targets: Iterable[str | Path], cancel=None) -> Iterator[ScanResult]:
        seen = set()
        for target in targets:
            if cancel and cancel.is_set():
                return
            root = Path(os.path.abspath(target))
            if root.is_dir() and not root.is_symlink():
                if self.quarantine_dir and inside(root, self.quarantine_dir):
                    yield ScanResult(str(root), "skipped", detail="Каталог карантина")
                    continue
                errors = []
                for directory, dirs, files in os.walk(root, followlinks=False, onerror=errors.append):
                    if cancel and cancel.is_set():
                        return
                    dirs[:] = sorted(d for d in dirs if not (Path(directory) / d).is_symlink()
                                     and not (self.quarantine_dir and inside(Path(directory) / d, self.quarantine_dir)))
                    for name in sorted(files):
                        if cancel and cancel.is_set():
                            return
                        path = Path(directory) / name
                        key = os.path.normcase(str(path))
                        if key not in seen:
                            seen.add(key)
                            yield self.scan_file(path, cancel)
                for exc in errors:
                    yield ScanResult(str(exc.filename or root), "error", detail=str(exc), engine=self.engine)
            else:
                key = os.path.normcase(str(root))
                if key not in seen:
                    seen.add(key)
                    yield self.scan_file(root, cancel)
