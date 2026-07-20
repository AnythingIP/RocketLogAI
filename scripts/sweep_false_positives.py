#!/usr/bin/env python3
"""Bulk-close home-lab false positive threats in a RocketLogAI SQLite DB.

Usage (on the server or with a local copy of the DB):
  python scripts/sweep_false_positives.py /path/to/logsentinel.db [--dry-run]
  python scripts/sweep_false_positives.py /srv/storage/logsentinel/data/logsentinel.db

Marks matching open threats as status=verified_benign with notes.
Does NOT delete rows (audit trail kept).
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running from repo root without install
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from logsentinel.noise import is_likely_false_positive_threat  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("db", type=Path, help="Path to logsentinel.db")
    ap.add_argument("--dry-run", action="store_true", help="Count only, no writes")
    ap.add_argument("--limit", type=int, default=0, help="Max rows to scan (0=all open)")
    args = ap.parse_args()

    if not args.db.is_file():
        print(f"DB not found: {args.db}", file=sys.stderr)
        return 2

    conn = sqlite3.connect(str(args.db))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    q = "SELECT id, severity, description, evidence, hostname, appname, source_ip FROM threats WHERE status = 'open'"
    if args.limit > 0:
        q += f" ORDER BY id DESC LIMIT {int(args.limit)}"
    rows = cur.execute(q).fetchall()

    reasons: dict[str, int] = {}
    ids: list[int] = []
    for r in rows:
        threat = {
            "severity": r["severity"],
            "description": r["description"] or "",
            "hostname": r["hostname"],
            "appname": r["appname"],
            "source_ip": r["source_ip"],
            "evidence": [],
        }
        try:
            threat["evidence"] = json.loads(r["evidence"] or "[]")
        except json.JSONDecodeError:
            threat["evidence"] = [r["evidence"] or ""]

        fp, reason = is_likely_false_positive_threat(threat)
        if fp:
            ids.append(int(r["id"]))
            reasons[reason] = reasons.get(reason, 0) + 1

    print(f"Scanned open threats: {len(rows)}")
    print(f"False positives to close: {len(ids)}")
    for k, v in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")

    if args.dry_run or not ids:
        print("Dry-run or nothing to do.")
        return 0

    now = datetime.now(timezone.utc).isoformat()
    note = "Bulk sweep: home-lab false positive (AP flow / LAN noise / HA lab noise)"
    cur.executemany(
        """
        UPDATE threats
        SET status = 'verified_benign',
            acknowledged_at = ?,
            notes = COALESCE(notes || ' | ', '') || ?
        WHERE id = ? AND status = 'open'
        """,
        [(now, note, i) for i in ids],
    )
    conn.commit()
    print(f"Updated {cur.rowcount if cur.rowcount > 0 else len(ids)} rows -> verified_benign")
    open_left = cur.execute("SELECT count(*) FROM threats WHERE status='open'").fetchone()[0]
    print(f"Open threats remaining: {open_left}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
