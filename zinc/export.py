"""Export one link's statistics for spreadsheets or scripts. Never writes IPs, the secret suffix or target URLs."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path

from .store import Link, Store

COLUMNS = ("time_utc", "kind", "country", "continent", "language", "variant", "visitor")


def safe_cell(value) -> str:
    """Spreadsheet formula injection: a cell starting with = + - @ would be executed by Excel/Sheets."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def export_link(store: Store, link: Link, folder: Path, now: float) -> list[Path]:
    """Write `zinc-<id>-hits.csv` and `zinc-<id>-summary.json` into `folder`. Returns the two paths."""
    folder.mkdir(parents=True, exist_ok=True)
    hits_path = folder / f"zinc-{link.id}-hits.csv"
    with hits_path.open("w", newline="", encoding="utf-8-sig") as f:      # BOM: Excel opens UTF-8 correctly
        w = csv.writer(f)
        w.writerow(COLUMNS)
        for row in store.all_hits(link.id):
            ts = datetime.fromtimestamp(row["ts"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            w.writerow([ts, row["kind"], safe_cell(row["country"]), safe_cell(row["continent"]),
                        safe_cell(row["lang"]), safe_cell(row["variant"]), (row["vid"] or "")[:8]])
    stats = store.stats(link.id, now)
    summary = {
        "id": link.id, "label": link.spec.label, "mode": link.spec.mode, "status": link.status,
        "created_utc": datetime.fromtimestamp(link.created_at, tz=timezone.utc).isoformat(timespec="seconds"),
        "expires_utc": (None if link.expires_at is None else
                        datetime.fromtimestamp(link.expires_at, tz=timezone.utc).isoformat(timespec="seconds")),
        "exported_utc": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(timespec="seconds"),
        "stats": {k: stats[k] for k in ("opens", "uniques", "passes", "pass_uniques", "bots",
                                        "by_country", "by_continent", "by_variant")},
    }
    summary_path = folder / f"zinc-{link.id}-summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return [hits_path, summary_path]
