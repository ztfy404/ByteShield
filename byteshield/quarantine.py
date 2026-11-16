"""Явный перенос файла в карантин и восстановление без перезаписи."""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from .paths import inside


def _fingerprint(s):
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns


def _hash(path):
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ValueError("Требуется обычный файл")
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Quarantine:
    def __init__(self, directory):
        self.directory = Path(directory).absolute()

    def _prepare(self):
        if self.directory.is_symlink():
            raise ValueError("Каталог карантина не должен быть ссылкой")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _record(self, identifier):
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise ValueError("Неверный ID карантина")
        path = self.directory / (identifier + ".json")
        if path.is_symlink():
            raise ValueError("Метаданные карантина не должны быть ссылкой")
        record = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(record, dict) or record.get("id") != identifier
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256", "")))
                or not isinstance(record.get("original_path"), str)):
            raise ValueError("Повреждена запись карантина")
        return record

    def add(self, path, expected_sha256):
        path = Path(os.path.abspath(path))
        self._prepare()
        if inside(path, self.directory):
            raise ValueError("Этот файл уже находится в карантине")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("В карантин можно переносить только обычные файлы")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ValueError("Требуется SHA-256 проверенного файла")
        identifier = uuid.uuid4().hex
        blob = self.directory / (identifier + ".bin")
        metadata = self.directory / (identifier + ".json")
        digest = hashlib.sha256()
        try:
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as src:
                if not stat.S_ISREG(os.fstat(src.fileno()).st_mode) or _fingerprint(os.fstat(src.fileno())) != _fingerprint(before):
                    raise ValueError("Файл изменился; проверьте его ещё раз")
                with os.fdopen(os.open(blob, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600), "wb") as out:
                    for chunk in iter(lambda: src.read(65536), b""):
                        digest.update(chunk)
                        out.write(chunk)
                    out.flush()
                    os.fsync(out.fileno())
                if _fingerprint(os.fstat(src.fileno())) != _fingerprint(before):
                    raise ValueError("Файл изменился во время переноса")
            if digest.hexdigest() != expected_sha256 or _hash(blob) != expected_sha256:
                raise ValueError("Содержимое изменилось; исходный файл сохранён")
            record = {"id": identifier, "original_path": str(path), "sha256": expected_sha256,
                      "created_at": datetime.now(timezone.utc).isoformat(), "size": before.st_size}
            with metadata.open("x", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2)
                f.flush()
                os.fsync(f.fileno())
            if _fingerprint(path.lstat()) != _fingerprint(before):
                raise ValueError("Исходный файл изменился; перенос отменён")
            # Удаление только после записи и проверки копии и метаданных.
            path.unlink()
            return record
        except Exception:
            # Если исходник остался на месте, незавершённую копию можно убрать.
            if path.exists():
                blob.unlink(missing_ok=True)
                metadata.unlink(missing_ok=True)
            raise

    def items(self):
        if not self.directory.exists():
            return []
        records = []
        for path in sorted(self.directory.glob("*.json")):
            records.append(self._record(path.stem))
        return records

    def restore(self, identifier, destination):
        record = self._record(identifier)
        blob = self.directory / (identifier + ".bin")
        if blob.is_symlink() or not stat.S_ISREG(blob.lstat().st_mode):
            raise ValueError("Повреждён файл карантина")
        destination = Path(os.path.abspath(destination))
        if inside(destination, self.directory):
            raise ValueError("Выберите путь вне карантина")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("Файл назначения уже существует; выберите другое имя")
        if _hash(blob) != record["sha256"]:
            raise ValueError("Контрольная сумма карантина не совпадает")
        created = False
        try:
            with destination.open("xb") as out:
                created = True
                with blob.open("rb") as source:
                    shutil.copyfileobj(source, out)
                out.flush()
                os.fsync(out.fileno())
            if _hash(destination) != record["sha256"]:
                raise ValueError("Не удалось проверить восстановленный файл")
        except Exception:
            if created:
                destination.unlink(missing_ok=True)
            raise
        # Копия остаётся в карантине: восстановление не уничтожает резерв.
        return destination
