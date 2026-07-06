"""Background task runner for AI Assistant operator execution.

Keeps long-running ping/LLM/Open Interpreter work off the main request thread
so the web UI stays responsive while tasks complete.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any, Awaitable, Callable


class AssistantTaskStore:
    def __init__(self, max_tasks: int = 200) -> None:
        self._tasks: dict[str, dict[str, Any]] = {}
        self._max_tasks = max_tasks
        self._lock = asyncio.Lock()

    async def create(self, label: str, user: str) -> str:
        task_id = str(uuid.uuid4())
        async with self._lock:
            self._prune_locked()
            self._tasks[task_id] = {
                "id": task_id,
                "label": label,
                "user": user,
                "status": "queued",
                "created_at": time.time(),
                "updated_at": time.time(),
                "result": None,
                "error": None,
            }
        return task_id

    async def update(self, task_id: str, **fields: Any) -> None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                return
            task.update(fields)
            task["updated_at"] = time.time()

    async def get(self, task_id: str) -> dict[str, Any] | None:
        async with self._lock:
            task = self._tasks.get(task_id)
            return dict(task) if task else None

    async def run(
        self,
        task_id: str,
        runner: Callable[[], Awaitable[dict[str, Any]]],
    ) -> None:
        await self.update(task_id, status="running")
        try:
            result = await runner()
            await self.update(task_id, status="completed", result=result, error=None)
        except Exception as exc:
            await self.update(
                task_id,
                status="failed",
                error=str(exc)[:500],
                result={"success": False, "error": str(exc)[:500]},
            )

    def _prune_locked(self) -> None:
        if len(self._tasks) <= self._max_tasks:
            return
        ordered = sorted(self._tasks.items(), key=lambda item: item[1].get("created_at", 0))
        for task_id, _ in ordered[: len(self._tasks) - self._max_tasks]:
            self._tasks.pop(task_id, None)


TASKS = AssistantTaskStore()