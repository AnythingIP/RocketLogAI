"""
Structured audit logging — immutable trail for all security-sensitive actions.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger("rocketlogai.audit")


class AuditLogger:
    """Tamper-evident audit log with structured JSON entries."""

    def __init__(self, db_path: str = "./data/audit/audit.db"):
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
            CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY,
                ts REAL NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT,
                outcome TEXT NOT NULL,
                details_json TEXT,
                ip_address TEXT,
                user_agent TEXT,
                tenant_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
            CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor);
            CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
        """)
        conn.commit()
        conn.close()

    def log(
        self,
        actor: str,
        action: str,
        outcome: str = "success",
        resource: str = "",
        details: dict[str, Any] | None = None,
        ip_address: str = "",
        user_agent: str = "",
        tenant_id: str = "",
    ) -> str:
        event_id = str(uuid.uuid4())
        entry = {
            "id": event_id,
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "resource": resource,
            "outcome": outcome,
            "details": details or {},
            "ip_address": ip_address,
            "user_agent": user_agent,
            "tenant_id": tenant_id,
        }
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO audit_events (id, ts, actor, action, resource, outcome, details_json, ip_address, user_agent, tenant_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, entry["ts"], actor, action, resource, outcome,
                json.dumps(details or {}), ip_address, user_agent, tenant_id,
            ),
        )
        conn.commit()
        conn.close()
        logger.info("AUDIT %s %s %s %s", actor, action, outcome, resource)
        return event_id

    def query(
        self,
        actor: str = "",
        action: str = "",
        since: float = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        conn = self._connect()
        sql = "SELECT * FROM audit_events WHERE ts >= ?"
        params: list[Any] = [since]
        if actor:
            sql += " AND actor = ?"
            params.append(actor)
        if action:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
        conn.close()
        return [
            {
                "id": r["id"],
                "ts": r["ts"],
                "actor": r["actor"],
                "action": r["action"],
                "resource": r["resource"],
                "outcome": r["outcome"],
                "details": json.loads(r["details_json"] or "{}"),
                "ip_address": r["ip_address"],
                "tenant_id": r["tenant_id"],
            }
            for r in rows
        ]