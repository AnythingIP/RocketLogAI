"""
MCP tool definitions for RocketLogAI ecosystem.
"""

from __future__ import annotations

from typing import Any, Callable


def build_default_tools(storage: Any = None, brain: Any = None) -> list[dict[str, Any]]:
    """Return MCP-compatible tool schemas."""

    async def search_logs(query: str = "", limit: int = 25, **_: Any) -> dict[str, Any]:
        if storage is None:
            return {"error": "storage not configured"}
        logs = storage.get_recent_logs(limit=limit) if hasattr(storage, "get_recent_logs") else []
        if query:
            q = query.lower()
            logs = [l for l in logs if q in (l.get("message") or "").lower()]
        return {"count": len(logs), "logs": logs[:limit]}

    async def list_threats(status: str = "open", limit: int = 20, **_: Any) -> dict[str, Any]:
        if storage is None:
            return {"error": "storage not configured"}
        threats = storage.get_threats(limit=limit, status=status) if hasattr(storage, "get_threats") else []
        return {"count": len(threats), "threats": threats}

    async def rag_search(query: str, **_: Any) -> dict[str, Any]:
        if brain is None:
            return {"error": "brain not configured"}
        ctx = brain.rag.build_context(query)
        return {"context": ctx, "hits": len(ctx.splitlines()) if ctx else 0}

    async def device_status(ip: str = "", **_: Any) -> dict[str, Any]:
        if storage is None or not ip:
            return {"error": "storage or ip required"}
        device = storage.get_known_device(ip) if hasattr(storage, "get_known_device") else None
        return {"device": device or {"ip": ip, "status": "unknown"}}

    return [
        {
            "name": "search_logs",
            "description": "Search recent syslog entries",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 25},
                },
            },
            "handler": search_logs,
        },
        {
            "name": "list_threats",
            "description": "List security threats by status",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "default": "open"},
                    "limit": {"type": "integer", "default": 20},
                },
            },
            "handler": list_threats,
        },
        {
            "name": "rag_search",
            "description": "Semantic search across logs, threats, and conversation memory",
            "inputSchema": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
            "handler": rag_search,
        },
        {
            "name": "device_status",
            "description": "Get device intelligence for an IP",
            "inputSchema": {
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
            "handler": device_status,
        },
    ]


def tool_handlers(tools: list[dict[str, Any]]) -> dict[str, Callable]:
    return {t["name"]: t["handler"] for t in tools if "handler" in t}