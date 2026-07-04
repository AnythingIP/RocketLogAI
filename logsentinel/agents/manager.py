"""
Agent lifecycle management — install, remove, migrate, wipe.
"""

from __future__ import annotations

import secrets
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any


class AgentManager:
    """Manage remote RocketAI agents on Windows/Mac/Linux."""

    def __init__(self, db_path: str = "./data/agents/agents.db"):
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
            CREATE TABLE IF NOT EXISTS agents (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                host TEXT,
                status TEXT DEFAULT 'pending',
                token_hash TEXT,
                sandbox_path TEXT,
                installed_at REAL,
                last_seen REAL,
                metadata_json TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status);
        """)
        conn.commit()
        conn.close()

    def register(
        self,
        name: str,
        platform: str,
        host: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        agent_id = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        sandbox = f"./data/agents/sandbox/{agent_id}"
        Path(sandbox).mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        conn.execute(
            """
            INSERT INTO agents (id, name, platform, host, status, token_hash, sandbox_path, installed_at, last_seen, metadata_json)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
            """,
            (agent_id, name, platform, host, token[:16], sandbox, time.time(), time.time(), str(metadata or {})),
        )
        conn.commit()
        conn.close()
        return {
            "id": agent_id,
            "install_token": f"rla_{token}",
            "sandbox_path": sandbox,
            "install_script_url": f"/api/v2/agents/{agent_id}/install.sh",
        }

    def heartbeat(self, agent_id: str) -> dict[str, Any]:
        conn = self._connect()
        conn.execute("UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?", (time.time(), agent_id))
        conn.commit()
        row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        conn.close()
        if not row:
            return {"error": "agent not found"}
        return {"id": agent_id, "status": "online", "last_seen": time.time()}

    def list_agents(self, status: str = "") -> list[dict[str, Any]]:
        conn = self._connect()
        if status:
            rows = conn.execute("SELECT id, name, platform, host, status, last_seen FROM agents WHERE status = ?", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT id, name, platform, host, status, last_seen FROM agents").fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def wipe_agent(self, agent_id: str, full_clean: bool = False) -> dict[str, Any]:
        conn = self._connect()
        row = conn.execute("SELECT sandbox_path FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if not row:
            conn.close()
            return {"error": "agent not found"}
        sandbox = row["sandbox_path"]
        if full_clean:
            conn.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
            status = "removed"
        else:
            conn.execute("UPDATE agents SET status = 'wiped' WHERE id = ?", (agent_id,))
            status = "sandbox_wiped"
        conn.commit()
        conn.close()
        return {"agent_id": agent_id, "status": status, "sandbox": sandbox}

    async def execute_command(self, agent_id: str, command: str) -> dict[str, Any]:
        conn = self._connect()
        row = conn.execute("SELECT name, platform, status FROM agents WHERE id = ?", (agent_id,)).fetchone()
        conn.close()
        if not row:
            return {"error": "agent not found"}
        if row["status"] not in ("online", "pending"):
            return {"error": f"agent status: {row['status']}"}
        return {
            "agent_id": agent_id,
            "command": command,
            "status": "queued",
            "message": f"Command queued for {row['name']} ({row['platform']})",
        }