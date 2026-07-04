"""
Conversation memory — persistent intent and context across AI sessions.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any


class ConversationMemory:
    """SQLite-backed conversation memory with intent tracking."""

    def __init__(self, db_path: str = "./data/brain/memory.db"):
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
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                intent TEXT,
                context_json TEXT,
                created_at REAL,
                updated_at REAL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                execution_result TEXT,
                ts REAL,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            );
            CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, ts);
        """)
        conn.commit()
        conn.close()

    def get_or_create_session(self, session_id: str, user_id: str = "", intent: str = "") -> dict[str, Any]:
        conn = self._connect()
        row = conn.execute("SELECT * FROM sessions WHERE id = ?", (session_id,)).fetchone()
        now = time.time()
        if row is None:
            conn.execute(
                "INSERT INTO sessions (id, user_id, intent, context_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, user_id, intent, "{}", now, now),
            )
            conn.commit()
            session = {"id": session_id, "user_id": user_id, "intent": intent, "context": {}}
        else:
            session = {
                "id": row["id"],
                "user_id": row["user_id"],
                "intent": row["intent"] or intent,
                "context": json.loads(row["context_json"] or "{}"),
            }
        conn.close()
        return session

    def set_intent(self, session_id: str, intent: str) -> None:
        conn = self._connect()
        conn.execute(
            "UPDATE sessions SET intent = ?, updated_at = ? WHERE id = ?",
            (intent, time.time(), session_id),
        )
        conn.commit()
        conn.close()

    def update_context(self, session_id: str, context: dict[str, Any]) -> None:
        conn = self._connect()
        conn.execute(
            "UPDATE sessions SET context_json = ?, updated_at = ? WHERE id = ?",
            (json.dumps(context), time.time(), session_id),
        )
        conn.commit()
        conn.close()

    def add_message(
        self,
        session_id: str,
        role: str,
        content: str,
        execution_result: str | None = None,
    ) -> int:
        conn = self._connect()
        cur = conn.execute(
            "INSERT INTO messages (session_id, role, content, execution_result, ts) VALUES (?, ?, ?, ?, ?)",
            (session_id, role, content, execution_result, time.time()),
        )
        conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (time.time(), session_id))
        conn.commit()
        msg_id = cur.lastrowid
        conn.close()
        return msg_id or 0

    def get_history(self, session_id: str, limit: int = 50) -> list[dict[str, Any]]:
        conn = self._connect()
        rows = conn.execute(
            "SELECT role, content, execution_result, ts FROM messages WHERE session_id = ? ORDER BY ts DESC LIMIT ?",
            (session_id, limit),
        ).fetchall()
        conn.close()
        return [
            {
                "role": r["role"],
                "content": r["content"],
                "execution_result": r["execution_result"],
                "ts": r["ts"],
            }
            for r in reversed(rows)
        ]

    def get_full_context(self, session_id: str) -> dict[str, Any]:
        session = self.get_or_create_session(session_id)
        session["history"] = self.get_history(session_id)
        return session