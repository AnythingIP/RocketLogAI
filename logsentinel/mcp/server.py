"""
MCP server implementation — JSON-RPC over stdio and HTTP/SSE.
"""

from __future__ import annotations

import json
import logging
import sys
import uuid
from typing import Any

logger = logging.getLogger(__name__)

MCP_VERSION = "2024-11-05"


class MCPServer:
    """Lightweight MCP server exposing RocketLogAI tools."""

    def __init__(self, name: str = "rocketlogai", version: str = "2.0.0", tools: list[dict[str, Any]] | None = None):
        self.name = name
        self.version = version
        self.tools = tools or []
        self._handlers = {t["name"]: t["handler"] for t in self.tools if "handler" in t}

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {k: v for k, v in t.items() if k != "handler"}
            for t in self.tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        handler = self._handlers.get(name)
        if not handler:
            return {"error": f"unknown tool: {name}"}
        try:
            result = await handler(**(arguments or {}))
            return {"content": [{"type": "text", "text": json.dumps(result, default=str)}]}
        except Exception as exc:
            logger.exception("MCP tool %s failed", name)
            return {"error": str(exc), "isError": True}

    async def handle_request(self, request: dict[str, Any]) -> dict[str, Any]:
        method = request.get("method", "")
        req_id = request.get("id", str(uuid.uuid4()))
        params = request.get("params") or {}

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": MCP_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": self.version},
                },
            }

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": self.list_tools()}}

        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            result = await self.call_tool(name, args)
            return {"jsonrpc": "2.0", "id": req_id, "result": result}

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }

    async def run_stdio(self) -> None:
        """Run MCP server on stdin/stdout (for Claude Desktop, Cursor, etc.)."""
        logger.info("MCP server %s v%s starting on stdio", self.name, self.version)
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = await self.handle_request(request)
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
                sys.stdout.write(json.dumps(err) + "\n")
                sys.stdout.flush()