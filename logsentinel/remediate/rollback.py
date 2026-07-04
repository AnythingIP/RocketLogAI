"""
Rollback support for remediation actions.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .backup import RemediationBackup


@dataclass
class RollbackPlan:
    id: str
    action_id: str
    target: str
    snapshot_id: str
    steps: list[str]
    status: str = "ready"  # ready | executed | failed
    created_at: float = field(default_factory=time.time)


class RollbackManager:
    """Manage rollback plans linked to remediation backups."""

    def __init__(self, backup: RemediationBackup | None = None):
        self.backup = backup or RemediationBackup()
        self._plans: dict[str, RollbackPlan] = {}

    def create_plan(self, action_id: str, target: str, snapshot_id: str, steps: list[str] | None = None) -> RollbackPlan:
        plan = RollbackPlan(
            id=str(uuid.uuid4()),
            action_id=action_id,
            target=target,
            snapshot_id=snapshot_id,
            steps=steps or [f"Restore snapshot {snapshot_id}", "Verify service health", "Log rollback completion"],
        )
        self._plans[plan.id] = plan
        return plan

    def execute(self, plan_id: str) -> dict[str, Any]:
        plan = self._plans.get(plan_id)
        if not plan:
            return {"status": "error", "reason": "plan not found"}

        result = self.backup.restore(plan.snapshot_id)
        if result.get("status") == "restored":
            plan.status = "executed"
            return {"status": "rolled_back", "plan_id": plan_id, "restore": result}
        plan.status = "failed"
        return {"status": "failed", "plan_id": plan_id, "restore": result}

    def list_plans(self, action_id: str | None = None) -> list[dict[str, Any]]:
        plans = []
        for p in self._plans.values():
            if action_id and p.action_id != action_id:
                continue
            plans.append({
                "id": p.id,
                "action_id": p.action_id,
                "target": p.target,
                "snapshot_id": p.snapshot_id,
                "status": p.status,
                "steps": p.steps,
                "created_at": p.created_at,
            })
        return plans