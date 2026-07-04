"""
Sync protocol for local-first mobile AI assistant.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any


class SyncManager:
    """Bidirectional sync between mobile clients and server."""

    def __init__(self, db_path: str = "./data/mobile/sync.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sync_items (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                item_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                version INTEGER DEFAULT 1,
                updated_at REAL,
                deleted INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS sync_cursors (
                device_id TEXT PRIMARY KEY,
                cursor TEXT,
                last_sync REAL
            );
            CREATE INDEX IF NOT EXISTS idx_sync_device ON sync_items(device_id, updated_at);
        """)
        conn.commit()
        conn.close()

    def push(self, device_id: str, items: list[dict[str, Any]]) -> dict[str, Any]:
        conn = self._connect()
        accepted = 0
        for item in items:
            item_id = item.get("id") or str(uuid.uuid4())
            conn.execute(
                """
                INSERT OR REPLACE INTO sync_items (id, device_id, item_type, payload, version, updated_at, deleted)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item_id,
                    device_id,
                    item.get("type", "message"),
                    json.dumps(item.get("payload", {})),
                    item.get("version", 1),
                    time.time(),
                    1 if item.get("deleted") else 0,
                ),
            )
            accepted += 1
        conn.execute(
            "INSERT OR REPLACE INTO sync_cursors (device_id, cursor, last_sync) VALUES (?, ?, ?)",
            (device_id, str(time.time()), time.time()),
        )
        conn.commit()
        conn.close()
        return {"accepted": accepted, "cursor": str(time.time())}

    def pull(self, device_id: str, since: float = 0) -> dict[str, Any]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT id, item_type, payload, version, updated_at, deleted FROM sync_items WHERE device_id = ? AND updated_at > ? ORDER BY updated_at",
            (device_id, since),
        ).fetchall()
        conn.close()
        items = [
            {
                "id": r["id"],
                "type": r["item_type"],
                "payload": json.loads(r["payload"]),
                "version": r["version"],
                "updated_at": r["updated_at"],
                "deleted": bool(r["deleted"]),
            }
            for r in rows
        ]
        return {"items": items, "cursor": str(time.time())}