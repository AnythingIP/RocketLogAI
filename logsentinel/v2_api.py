"""
FastAPI router for RocketLogAI v2 ecosystem APIs.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v2", tags=["v2"])


def _get_runtime():
    from .v2_runtime import get_v2_runtime
    from .web import _cfg, _storage
    return get_v2_runtime(_cfg, _storage)


def _require_login(request: Request):
    from .web import require_login
    return require_login(request)


class RemediateRequest(BaseModel):
    action_type: str
    target: str
    reason: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = True
    approval_id: str | None = None


class MobilePairRequest(BaseModel):
    code: str
    device_id: str
    platform: str = "unknown"


class MobileQueryRequest(BaseModel):
    query: str
    voice: bool = False


class TaskUpdateRequest(BaseModel):
    status: str
    assigned_to: str = ""
    notes: str = ""


@router.get("/status")
async def v2_status(user: str = Depends(_require_login)):
    rt = _get_runtime()
    return rt.status()


@router.get("/metrics")
async def prometheus_metrics():
    rt = _get_runtime()
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(rt.metrics.export_prometheus(), media_type="text/plain; version=0.0.4")


@router.get("/audit")
async def audit_log(limit: int = 50, user: str = Depends(_require_login)):
    rt = _get_runtime()
    return {"events": rt.audit.query(limit=limit)}


@router.post("/brain/ask")
async def brain_ask(request: Request, user: str = Depends(_require_login)):
    body = await request.json()
    query = body.get("query", "")
    session_id = body.get("session_id", f"web:{user}")
    rt = _get_runtime()
    rt.audit.log(user, "brain.ask", resource=session_id, details={"query": query[:200]})

    llm_call = None
    if rt.storage:
        try:
            from .llm import create_llm_client
            llm = create_llm_client(rt.cfg)
            async def _call(prompt: str) -> str:
                return await llm.complete(prompt)
            llm_call = _call
        except Exception:
            pass

    return await rt.brain.ask(session_id, query, user_id=user, llm_call=llm_call)


@router.post("/remediate/dry-run")
async def remediate_dry_run(req: RemediateRequest, user: str = Depends(_require_login)):
    from .remediate.engine import RemediationAction
    rt = _get_runtime()
    action = RemediationAction(req.action_type, req.target, req.reason, req.parameters)
    result = await rt.remediate.dry_run(action, requested_by=user)
    rt.audit.log(user, "remediate.dry_run", resource=req.target, details={"action": req.action_type})
    return result.__dict__


@router.post("/remediate/execute")
async def remediate_execute(req: RemediateRequest, user: str = Depends(_require_login)):
    from .remediate.engine import RemediationAction
    rt = _get_runtime()
    action = RemediationAction(req.action_type, req.target, req.reason, req.parameters)
    result = await rt.remediate.execute(action, confirmed=True, approved_by=user, approval_id=req.approval_id)
    rt.audit.log(user, "remediate.execute", outcome=result.status, resource=req.target)
    return result.__dict__


@router.get("/remediate/approvals")
async def list_approvals(user: str = Depends(_require_login)):
    rt = _get_runtime()
    pending = rt.remediate.approval.list_pending()
    return {"pending": [p.__dict__ for p in pending]}


@router.post("/remediate/approvals/{approval_id}/approve")
async def approve_remediation(approval_id: str, user: str = Depends(_require_login)):
    rt = _get_runtime()
    req = rt.remediate.approval.approve(approval_id, user)
    if not req:
        raise HTTPException(404, "Approval not found or already processed")
    rt.audit.log(user, "remediate.approve", resource=approval_id)
    return req.__dict__


@router.get("/shield/status")
async def shield_status(user: str = Depends(_require_login)):
    rt = _get_runtime()
    return {
        "config": {
            "enabled": rt.shield_config.enabled,
            "mode": rt.shield_config.mode.value,
        },
        "waf": rt.waf.status(),
        "av": rt.av.status(),
        "parental": rt.parental.status(),
    }


@router.post("/shield/inspect")
async def shield_inspect(request: Request, user: str = Depends(_require_login)):
    body = await request.json()
    rt = _get_runtime()
    waf_result = rt.waf.inspect(body)
    av_result = rt.av.scan_http_body(body.get("body", ""), source_ip=body.get("source_ip", ""))
    return {"waf": waf_result, "av": av_result}


@router.get("/ueba/anomalies")
async def ueba_anomalies(limit: int = 50, user: str = Depends(_require_login)):
    rt = _get_runtime()
    return {"anomalies": rt.ueba.recent_anomalies(limit)}


@router.get("/ueba/report")
async def ueba_report(hours: int = 24, user: str = Depends(_require_login)):
    rt = _get_runtime()
    return rt.ueba_reports.generate_summary(rt.ueba.recent_anomalies(500), period_hours=hours)


@router.get("/agents")
async def list_agents(user: str = Depends(_require_login)):
    rt = _get_runtime()
    return {"agents": rt.agents.list_agents()}


@router.post("/agents/register")
async def register_agent(request: Request, user: str = Depends(_require_login)):
    body = await request.json()
    rt = _get_runtime()
    result = rt.agents.register(body.get("name", "agent"), body.get("platform", "unknown"), body.get("host", ""))
    rt.audit.log(user, "agent.register", resource=result.get("id", ""))
    return result


def _agent_install_script(agent_id: str, token: str, platform: str, server_base: str) -> str:
    base = server_base.rstrip("/")
    if platform == "windows":
        return (
            f"# RocketLogAI Agent installer (Windows)\n"
            f"# Run in PowerShell on the target machine:\n"
            f"$env:RLA_SERVER = '{base}'\n"
            f"$env:RLA_AGENT_ID = '{agent_id}'\n"
            f"$env:RLA_AGENT_TOKEN = '{token}'\n"
            f"Invoke-RestMethod -Uri \"$env:RLA_SERVER/api/v2/agents/heartbeat\" "
            f"-Method POST -Headers @{{'X-Agent-ID'=$env:RLA_AGENT_ID;'Authorization'=\"Bearer $env:RLA_AGENT_TOKEN\"}}\n"
            f"Write-Host 'Agent registered. Keep this token secret.'\n"
        )
    return (
        f"#!/usr/bin/env bash\n"
        f"# RocketLogAI Agent installer (Linux/macOS)\n"
        f"set -euo pipefail\n"
        f"export RLA_SERVER='{base}'\n"
        f"export RLA_AGENT_ID='{agent_id}'\n"
        f"export RLA_AGENT_TOKEN='{token}'\n"
        f"curl -fsS -X POST \"$RLA_SERVER/api/v2/agents/heartbeat\" \\\n"
        f"  -H \"X-Agent-ID: $RLA_AGENT_ID\" -H \"Authorization: Bearer $RLA_AGENT_TOKEN\"\n"
        f"echo 'Agent registered. Keep this token secret.'\n"
    )


@router.get("/agents/{agent_id}/install.sh")
async def agent_install_sh(agent_id: str, request: Request, user: str = Depends(_require_login)):
    from fastapi.responses import PlainTextResponse
    rt = _get_runtime()
    agents = rt.agents.list_agents()
    row = next((a for a in agents if a.get("id") == agent_id), None)
    if not row:
        raise HTTPException(404, "Agent not found")
    token = f"rla_{agent_id}"
    script = _agent_install_script(agent_id, token, row.get("platform", "linux"), str(request.base_url).rstrip("/"))
    return PlainTextResponse(script, media_type="text/plain")


@router.get("/agents/{agent_id}/install.ps1")
async def agent_install_ps1(agent_id: str, request: Request, user: str = Depends(_require_login)):
    from fastapi.responses import PlainTextResponse
    rt = _get_runtime()
    agents = rt.agents.list_agents()
    row = next((a for a in agents if a.get("id") == agent_id), None)
    if not row:
        raise HTTPException(404, "Agent not found")
    token = f"rla_{agent_id}"
    script = _agent_install_script(agent_id, token, "windows", str(request.base_url).rstrip("/"))
    return PlainTextResponse(script, media_type="text/plain")


@router.post("/agents/heartbeat")
async def agent_heartbeat(request: Request):
    agent_id = request.headers.get("X-Agent-ID", "")
    if not agent_id:
        raise HTTPException(400, "X-Agent-ID required")
    rt = _get_runtime()
    return rt.agents.heartbeat(agent_id)


@router.post("/mobile/pair")
async def mobile_pair(req: MobilePairRequest):
    rt = _get_runtime()
    return rt.mobile.pair_device(req.code, req.device_id, req.platform)


@router.get("/mobile/qr")
async def mobile_qr(user: str = Depends(_require_login)):
    rt = _get_runtime()
    return rt.mobile.generate_pairing_qr(user_id=user)


@router.post("/mobile/assistant")
async def mobile_assistant(req: MobileQueryRequest, request: Request):
    device_id = request.headers.get("X-Device-ID", "unknown")
    rt = _get_runtime()
    return await rt.mobile.assistant_query(device_id, req.query, voice=req.voice)


@router.get("/tasks")
async def list_tasks(status: str = "", user: str = Depends(_require_login)):
    from .web import _storage
    if not _storage:
        return {"tasks": []}
    tasks = _storage.list_org_tasks(status=status) if hasattr(_storage, "list_org_tasks") else []
    return {"tasks": tasks}


@router.post("/tasks")
async def create_task(request: Request, user: str = Depends(_require_login)):
    from .web import _storage
    body = await request.json()
    if not _storage or not hasattr(_storage, "create_org_task"):
        raise HTTPException(501, "Task storage not available")
    task_id = _storage.create_org_task(
        title=body.get("title", "Untitled"),
        description=body.get("description", ""),
        severity=body.get("severity", "medium"),
        source=body.get("source", "manual"),
        created_by=user,
        threat_id=body.get("threat_id"),
    )
    rt = _get_runtime()
    rt.audit.log(user, "task.create", resource=str(task_id))
    return {"id": task_id}


@router.patch("/tasks/{task_id}")
async def update_task(task_id: int, req: TaskUpdateRequest, user: str = Depends(_require_login)):
    from .web import _storage
    if not _storage or not hasattr(_storage, "update_org_task"):
        raise HTTPException(501, "Task storage not available")
    ok = _storage.update_org_task(task_id, status=req.status, assigned_to=req.assigned_to, notes=req.notes, actor=user)
    if not ok:
        raise HTTPException(404, "Task not found")
    return {"success": True}


@router.get("/compliance/{framework}")
async def compliance_report(framework: str, user: str = Depends(_require_login)):
    from .integrations.compliance import ComplianceReporter
    rt = _get_runtime()
    reporter = ComplianceReporter(storage=rt.storage, audit=rt.audit)
    return reporter.assess(framework)


@router.post("/mcp/tools/call")
async def mcp_tool_call(request: Request, user: str = Depends(_require_login)):
    body = await request.json()
    rt = _get_runtime()
    result = await rt.mcp.call_tool(body.get("name", ""), body.get("arguments"))
    return result


@router.get("/mcp/tools")
async def mcp_tools_list(user: str = Depends(_require_login)):
    rt = _get_runtime()
    return {"tools": rt.mcp.list_tools()}