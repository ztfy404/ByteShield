import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from . import __version__


def make_report(results, engine, cancelled=False):
    rows = [r.to_dict() for r in results]
    return {"application": "ByteShield", "version": __version__,
            "finished_at": datetime.now(timezone.utc).isoformat(), "engine": engine,
            "cancelled": cancelled, "counts": dict(Counter(r["status"] for r in rows)),
            "results": rows}


def save_report(path, report):
    path = Path(path).absolute()
    fd, temp = tempfile.mkstemp(prefix=".byteshield-report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(temp, path)
    finally:
        Path(temp).unlink(missing_ok=True)
