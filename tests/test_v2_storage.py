"""Tests for v2 storage extensions."""

import tempfile
from pathlib import Path

from logsentinel.storage import Storage


def test_org_tasks_crud():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "test.db"
        storage = Storage(str(db))
        task_id = storage.create_org_task("Fix SSH brute force", severity="high", created_by="admin")
        assert task_id > 0
        tasks = storage.list_org_tasks(status="open")
        assert any(t["id"] == task_id for t in tasks)
        ok = storage.update_org_task(task_id, status="acknowledged", actor="admin")
        assert ok is True


def test_user_preferences():
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "test.db"
        storage = Storage(str(db))
        storage.set_user_preference("admin", "last_briefing_id", "42")
        val = storage.get_user_preference("admin", "last_briefing_id")
        assert val == "42"