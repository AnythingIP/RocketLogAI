"""
Entity behavior baselines for UEBA.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class BaselineStore:
    """Store and retrieve behavioral baselines per entity."""

    def __init__(self, db_path: str = "./data/ueba/baselines.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS baselines (
                entity_id TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                sample_count INTEGER DEFAULT 0,
                updated_at REAL
            )
        """)
        conn.commit()
        conn.close()

    def update(self, entity_id: str, entity_type: str, metrics: dict[str, Any]) -> None:
        conn = self._connect()
        row = conn.execute("SELECT metrics_json, sample_count FROM baselines WHERE entity_id = ?", (entity_id,)).fetchone()
        if row:
            existing = json.loads(row["metrics_json"])
            count = row["sample_count"] + 1
            merged = self._merge_metrics(existing, metrics, count)
        else:
            merged = metrics
            count = 1
        conn.execute(
            """
            INSERT OR REPLACE INTO baselines (entity_id, entity_type, metrics_json, sample_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (entity_id, entity_type, json.dumps(merged), count, time.time()),
        )
        conn.commit()
        conn.close()

    @staticmethod
    def _merge_metrics(existing: dict, new: dict, count: int) -> dict:
        merged = dict(existing)
        for k, v in new.items():
            if isinstance(v, (int, float)):
                old = existing.get(k, v)
                merged[k] = old + (v - old) / count
            elif isinstance(v, list):
                merged[k] = list(set((existing.get(k) or []) + v))[:50]
            else:
                merged[k] = v
        return merged

    def get(self, entity_id: str) -> dict[str, Any] | None:
        conn = self._connect()
        row = conn.execute("SELECT * FROM baselines WHERE entity_id = ?", (entity_id,)).fetchone()
        conn.close()
        if not row:
            return None
        return {
            "entity_id": row["entity_id"],
            "entity_type": row["entity_type"],
            "metrics": json.loads(row["metrics_json"]),
            "sample_count": row["sample_count"],
            "updated_at": row["updated_at"],
        }