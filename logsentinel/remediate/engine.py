"""
RocketRemediate engine — production remediation with safety rails.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..config import Config
from .approval import ApprovalWorkflow
from .backup import RemediationBackup
from .rollback import RollbackManager

logger = logging.getLogger(__name__)


@dataclass
class RemediationAction:
    action_type: str
    target: str
    reason: str
    parameters: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class RemediationResult:
    action_id: str
    status: str
    message: str
    dry_run: bool = True
    approval_id: str | None = None
    backup_id: str | None = None
    rollback_plan_id: str | None = None
    output: dict[str, Any] = field(default_factory=dict)


class RemediationEngine:
    """
    Production remediation engine with dry-run, approval, backup, and rollback.
    Replaces the legacy stub in logsentinel/remediation.py for v2.
    """

    PLUGIN_ACTIONS = {
        "block_ip": "firewall",
        "isolate_host": "network",
        "collect_forensics": "forensics",
        "update_ssh": "package",
        "run_script": "script",
        "restart_service": "service",
    }

    def __init__(self, cfg: Config, storage: Any = None):
        self.cfg = cfg
        self.storage = storage
        self.approval = ApprovalWorkflow()
        self.backup = RemediationBackup()
        self.rollback = RollbackManager(self.backup)
        self._action_count = 0
        self._hour_start = time.time()
        self._plugins: dict[str, Any] = {}

    def register_plugin(self, action_type: str, plugin: Any) -> None:
        self._plugins[action_type] = plugin

    def is_enabled(self) -> bool:
        return self.cfg.remediation.enabled

    def _rate_limit_ok(self) -> bool:
        now = time.time()
        if now - self._hour_start > 3600:
            self._hour_start = now
            self._action_count = 0
        return self._action_count < self.cfg.remediation.max_actions_per_hour

    def _action_allowed(self, action_type: str) -> bool:
        allowed = self.cfg.remediation.allowed_actions
        if not allowed:
            return True
        return action_type in allowed

    async def suggest_actions(self, threats: list[dict[str, Any]]) -> list[RemediationAction]:
        suggestions: list[RemediationAction] = []
        for t in threats:
            sev = t.get("severity", "medium")
            host = t.get("hostname") or t.get("source_ip") or "unknown"
            desc = t.get("description", "")

            if sev in ("critical", "high"):
                suggestions.append(RemediationAction(
                    action_type="isolate_host",
                    target=host,
                    reason=f"High severity: {desc}",
                    parameters={"duration_minutes": 30},
                ))
                suggestions.append(RemediationAction(
                    action_type="collect_forensics",
                    target=host,
                    reason="Capture volatile data",
                    parameters={"include": ["ps", "netstat", "auth.log"]},
                ))

            if "brute" in desc.lower() or "ssh" in desc.lower():
                ip = t.get("source_ip") or host
                suggestions.append(RemediationAction(
                    action_type="block_ip",
                    target=ip,
                    reason="Brute force detected",
                    parameters={"duration": "1h"},
                ))

        return suggestions

    async def dry_run(self, action: RemediationAction, requested_by: str = "system") -> RemediationResult:
        """Simulate action without making changes."""
        output = {
            "would_execute": action.action_type,
            "target": action.target,
            "parameters": action.parameters,
            "plugin": self.PLUGIN_ACTIONS.get(action.action_type, "generic"),
            "allowed": self._action_allowed(action.action_type),
            "rate_limit_ok": self._rate_limit_ok(),
        }
        approval = self.approval.create(
            action_type=action.action_type,
            target=action.target,
            reason=action.reason,
            parameters=action.parameters,
            requested_by=requested_by,
            dry_run_result=output,
        )
        return RemediationResult(
            action_id=action.id,
            status="dry_run",
            message=f"Dry-run complete for {action.action_type} on {action.target}",
            dry_run=True,
            approval_id=approval.id,
            output=output,
        )

    async def execute(
        self,
        action: RemediationAction,
        *,
        confirmed: bool = False,
        approved_by: str = "",
        approval_id: str | None = None,
        backup_files: list[str] | None = None,
    ) -> RemediationResult:
        if not self.cfg.remediation.enabled:
            return RemediationResult(action.id, "refused", "Remediation disabled in config")

        if self.cfg.remediation.dry_run:
            return await self.dry_run(action)

        if not self._action_allowed(action.action_type):
            return RemediationResult(action.id, "refused", f"Action type {action.action_type} not in allow-list")

        if not self._rate_limit_ok():
            return RemediationResult(action.id, "refused", "Rate limit exceeded")

        if self.cfg.remediation.require_confirmation and not confirmed:
            if approval_id:
                req = self.approval.get(approval_id)
                if not req or req.status != "approved":
                    return RemediationResult(
                        action.id, "requires_approval",
                        "Action requires human approval",
                        approval_id=approval_id,
                    )
            else:
                approval = self.approval.create(
                    action_type=action.action_type,
                    target=action.target,
                    reason=action.reason,
                    parameters=action.parameters,
                    requested_by=approved_by or "unknown",
                )
                return RemediationResult(
                    action.id, "requires_approval",
                    "Submit for approval before execution",
                    approval_id=approval.id,
                )

        snap = self.backup.create_snapshot(action.id, action.target, files=backup_files)
        rollback_plan = self.rollback.create_plan(action.id, action.target, snap["id"])

        plugin = self._plugins.get(action.action_type)
        output: dict[str, Any] = {"snapshot": snap["id"]}

        if plugin and hasattr(plugin, "execute"):
            try:
                output["plugin_result"] = await plugin.execute(action)
            except Exception as exc:
                logger.exception("Plugin execution failed")
                return RemediationResult(
                    action.id, "failed", str(exc),
                    backup_id=snap["id"],
                    rollback_plan_id=rollback_plan.id,
                    output=output,
                )
        else:
            output["simulated"] = True
            output["message"] = f"No plugin for {action.action_type}; logged for audit"

        self._action_count += 1
        self._audit(action, output, approved_by)

        return RemediationResult(
            action.id, "executed",
            f"Executed {action.action_type} on {action.target}",
            dry_run=False,
            backup_id=snap["id"],
            rollback_plan_id=rollback_plan.id,
            output=output,
        )

    def _audit(self, action: RemediationAction, output: dict[str, Any], actor: str) -> None:
        if self.storage and hasattr(self.storage, "log_activity"):
            self.storage.log_activity(
                category="remediation",
                action=action.action_type,
                details=f"{action.target}: {action.reason}",
                actor=actor or "system",
                metadata=output,
            )
        logger.info("REMEDIATION AUDIT: %s on %s by %s", action.action_type, action.target, actor)

    def get_status(self) -> dict[str, Any]:
        return {
            "enabled": self.cfg.remediation.enabled,
            "dry_run": self.cfg.remediation.dry_run,
            "require_confirmation": self.cfg.remediation.require_confirmation,
            "actions_this_hour": self._action_count,
            "pending_approvals": len(self.approval.list_pending()),
            "plugins": list(self._plugins.keys()),
        }