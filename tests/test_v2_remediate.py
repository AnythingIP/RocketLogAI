"""Tests for RocketRemediate engine."""

import asyncio

from logsentinel.config import Config
from logsentinel.remediate.engine import RemediationEngine, RemediationAction
from logsentinel.remediate.approval import ApprovalWorkflow


def test_remediation_dry_run_by_default():
    cfg = Config()
    cfg.remediation.enabled = True
    engine = RemediationEngine(cfg)
    action = RemediationAction("block_ip", "10.0.0.55", "brute force")
    result = asyncio.run(engine.dry_run(action, "admin"))
    assert result.status == "dry_run"
    assert result.approval_id is not None


def test_remediation_refused_when_disabled():
    cfg = Config()
    engine = RemediationEngine(cfg)
    action = RemediationAction("block_ip", "10.0.0.55", "test")
    result = asyncio.run(engine.execute(action, confirmed=True))
    assert result.status == "refused"


def test_approval_workflow():
    wf = ApprovalWorkflow()
    req = wf.create("block_ip", "10.0.0.1", "test", {}, "admin")
    assert req.status == "pending"
    approved = wf.approve(req.id, "supervisor")
    assert approved is not None
    assert approved.status == "approved"