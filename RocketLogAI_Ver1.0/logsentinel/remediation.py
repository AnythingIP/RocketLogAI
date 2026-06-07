"""
Remediation engine (STUB + SAFETY FIRST).

Automated "plug into devices to fix them" is extremely dangerous.
This module is intentionally minimal and disabled by default.

Future design goals (when you decide to implement):
- Explicit allow-list of hosts + action types
- Dry-run always available and default
- Human approval workflow (CLI or web UI)
- Full audit log of every attempted action
- Circuit breakers + rate limits
- SSH / API / agent-based responders as plugins
- Rollback / "blast radius" controls

For now: everything is a no-op unless you explicitly enable it in config AND code.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .config import Config

logger = logging.getLogger(__name__)


@dataclass
class RemediationAction:
    action_type: str
    target: str
    reason: str
    parameters: dict[str, Any]


class RemediationEngine:
    """
    Placeholder remediation engine.

    All methods currently refuse to do anything unless:
      - remediation.enabled = true in config
      - remediation.dry_run = false (still not recommended)
    """

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._action_count = 0
        self._last_action_time = 0.0

    def is_enabled(self) -> bool:
        return self.cfg.remediation.enabled

    def would_execute(self) -> bool:
        """True only if fully armed (dangerous)."""
        return (
            self.cfg.remediation.enabled
            and not self.cfg.remediation.dry_run
            and not self.cfg.remediation.require_confirmation
        )

    async def suggest_actions(self, threats: list[dict[str, Any]]) -> list[RemediationAction]:
        """
        Given a list of threat dicts, return recommended safe actions.

        This is the safe path: suggestions only, no execution.
        """
        suggestions: list[RemediationAction] = []

        for t in threats:
            sev = t.get("severity", "medium")
            host = t.get("hostname") or "unknown"
            desc = t.get("description", "")

            if sev in ("critical", "high"):
                suggestions.append(RemediationAction(
                    action_type="isolate_host",
                    target=host,
                    reason=f"High severity threat: {desc}",
                    parameters={"method": "network_segmentation", "duration_minutes": 30},
                ))
                suggestions.append(RemediationAction(
                    action_type="collect_forensics",
                    target=host,
                    reason="Capture volatile data and logs for later investigation",
                    parameters={"include": ["ps", "netstat", "last", "auth.log"]},
                ))

            if "brute" in desc.lower() or "ssh" in desc.lower():
                suggestions.append(RemediationAction(
                    action_type="block_ip",
                    target=host,
                    reason="Brute force detected - block source IP at firewall",
                    parameters={"duration": "1h"},
                ))

            # Heartbeat / monitor driven suggestions
            if t.get("appname") == "heartbeat" or "heartbeat" in desc.lower():
                if "ssh" in desc.lower() or "version" in desc.lower():
                    suggestions.append(RemediationAction(
                        action_type="update_ssh",
                        target=host,
                        reason=f"Outdated or unexpected SSH version detected: {desc}",
                        parameters={"suggested_command": "Update OpenSSH via package manager (apt/yum/dnf)"},
                    ))

        return suggestions

    async def execute(self, action: RemediationAction, *, confirmed: bool = False) -> dict[str, Any]:
        """
        Execute (or dry-run) a remediation action.

        This is the dangerous path. Currently always refuses unless you have
        both enabled remediation AND set dry_run=false AND require_confirmation=false.
        """
        if not self.cfg.remediation.enabled:
            return {"status": "refused", "reason": "remediation disabled in config"}

        if self.cfg.remediation.dry_run:
            logger.warning("DRY-RUN: would have executed %s on %s", action.action_type, action.target)
            return {
                "status": "dry_run",
                "action": action.action_type,
                "target": action.target,
                "would_have": True,
            }

        if self.cfg.remediation.require_confirmation and not confirmed:
            return {
                "status": "requires_confirmation",
                "action": action.action_type,
                "target": action.target,
            }

        if self.would_execute():
            # === REAL DANGEROUS CODE WOULD GO HERE ===
            if action.action_type == "update_ssh":
                # Very conservative: we only ever suggest or log the command.
                # Real execution would require explicit allow-listing of hosts + keys.
                cmd = self._generate_ssh_update_command(action.target)
                logger.warning("REMEDIATION: update_ssh requested for %s. Suggested: %s", action.target, cmd)
                return {
                    "status": "suggested",
                    "action": "update_ssh",
                    "target": action.target,
                    "command": cmd,
                    "warning": "This action requires manual review. Never auto-execute remote package updates without strong controls."
                }

            logger.critical("!!! REMEDIATION EXECUTION PATH REACHED - THIS SHOULD NEVER HAPPEN IN PRODUCTION WITHOUT AUDIT !!!")
            self._action_count += 1
            return {"status": "executed", "action": action.action_type, "target": action.target}

        return {"status": "refused", "reason": "safety interlocks not satisfied"}

    async def _ssh_command(self, host: str, cmd: str) -> str:
        """Future: implement via paramiko / asyncssh with strict key + host allow-list."""
        raise NotImplementedError("SSH responder not implemented")

    def _generate_ssh_update_command(self, host: str) -> str:
        """Return a safe, OS-aware suggestion for updating OpenSSH."""
        # In a real implementation we would SSH in and detect the OS.
        # For now we give the user the most common safe commands.
        return (
            f"# On Debian/Ubuntu:\n"
            f"ssh {host} 'sudo apt update && sudo apt install --only-upgrade openssh-server -y'\n\n"
            f"# On RHEL/CentOS/Fedora:\n"
            f"ssh {host} 'sudo dnf update openssh-server -y || sudo yum update openssh-server -y'\n\n"
            f"# Always review the exact package name and test in a staging environment first."
        )

    def get_status(self) -> dict[str, Any]:
        return {
            "enabled": self.cfg.remediation.enabled,
            "dry_run": self.cfg.remediation.dry_run,
            "require_confirmation": self.cfg.remediation.require_confirmation,
            "actions_taken_this_session": self._action_count,
            "armed": self.would_execute(),
        }
