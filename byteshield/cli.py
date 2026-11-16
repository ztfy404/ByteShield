import argparse
import json
import sys
from pathlib import Path
from .paths import data_dir
from .quarantine import Quarantine, _hash
from .report import make_report, save_report
from .scanner import Scanner


def main(argv=None):
    parser = argparse.ArgumentParser(prog="byteshield", description="ByteShield — проверка файлов по запросу")
    parser.add_argument("--quarantine-dir", type=Path, default=data_dir() / "quarantine")
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan", help="Проверить файлы или папки без удаления")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument("--engine", choices=["auto", "builtin", "clamav"], default="auto")
    scan.add_argument("--signatures", type=Path)
    scan.add_argument("--max-size-mb", type=float, default=128)
    scan.add_argument("--report", type=Path)
    quarantine = commands.add_parser("quarantine", help="Явно перенести выбранный файл")
    quarantine.add_argument("path", type=Path)
    commands.add_parser("list", help="Показать карантин")
    restore = commands.add_parser("restore", help="Восстановить копию, не перезаписывая файлы")
    restore.add_argument("id")
    restore.add_argument("--to", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        storage = Quarantine(args.quarantine_dir)
        if args.command == "scan":
            scanner = Scanner(args.engine, args.signatures, args.max_size_mb, args.quarantine_dir)
            print("Движок:", scanner.description)
            results = []
            for result in scanner.scan(args.paths):
                results.append(result)
                print(f"[{result.status}] {result.path}" + (f" — {result.threat or result.detail}" if result.threat or result.detail else ""))
            report = make_report(results, scanner.description)
            print("Итого:", json.dumps(report["counts"], ensure_ascii=False))
            if args.report:
                save_report(args.report, report)
            if any(r.status == "error" for r in results):
                return 2
            return 1 if any(r.status == "detected" for r in results) else 0
        if args.command == "quarantine":
            if args.path.is_symlink():
                raise ValueError("Ссылки в карантин не переносятся")
            record = storage.add(args.path, _hash(args.path))
            print(json.dumps(record, ensure_ascii=False, indent=2))
        elif args.command == "list":
            print(json.dumps(storage.items(), ensure_ascii=False, indent=2))
        elif args.command == "restore":
            print("Восстановлена копия:", storage.restore(args.id, args.to))
        return 0
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Проверка прервана", file=sys.stderr)
        return 130
