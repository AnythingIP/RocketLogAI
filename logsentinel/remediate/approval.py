"""
Approval workflow for remediation actions.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ApprovalRequest:
    id: str
    action_type: str
    target: str
    reason: str
    parameters: dict[str, Any]
    requested_by: str
    status: str = "pending"  # pending | approved | rejected | expired
    created_at: float = field(default_factory=time.time)
    approved_by: str = ""
    approved_at: float | None = None
    dry_run_result: dict[str, Any] | None = None


class ApprovalWorkflow:
    """Human-in-the-loop approval for remediation actions."""

    def __init__(self, ttl_seconds: int = 3600):
        self.ttl_seconds = ttl_seconds
        self._requests: dict[str, ApprovalRequest] = {}

    def create(
        self,
        action_type: str,
        target: str,
        reason: str,
        parameters: dict[str, Any],
        requested_by: str,
        dry_run_result: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        req = ApprovalRequest(
            id=str(uuid.uuid4()),
            action_type=action_type,
            target=target,
            reason=reason,
            parameters=parameters,
            requested_by=requested_by,
            dry_run_result=dry_run_result,
        )
        self._requests[req.id] = req
        return req

    def approve(self, request_id: str, approved_by: str) -> ApprovalRequest | None:
        req = self._requests.get(request_id)
        if not req or req.status != "pending":
            return None
        req.status = "approved"
        req.approved_by = approved_by
        req.approved_at = time.time()
        return req

    def reject(self, request_id: str, rejected_by: str) -> ApprovalRequest | None:
        req = self._requests.get(request_id)
        if not req or req.status != "pending":
            return None
        req.status = "rejected"
        req.approved_by = rejected_by
        req.approved_at = time.time()
        return req

    def get(self, request_id: str) -> ApprovalRequest | None:
        req = self._requests.get(request_id)
        if req and req.status == "pending" and (time.time() - req.created_at) > self.ttl_seconds:
            req.status = "expired"
        return req

    def list_pending(self) -> list[ApprovalRequest]:
        now = time.time()
        pending = []
        for req in self._requests.values():
            if req.status == "pending":
                if (now - req.created_at) > self.ttl_seconds:
                    req.status = "expired"
                else:
                    pending.append(req)
        return pending