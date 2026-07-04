"""Tests for MCP server."""

import asyncio

from logsentinel.mcp.server import MCPServer
from logsentinel.mcp.tools import build_default_tools


def test_mcp_initialize_and_list_tools():
    tools = build_default_tools()
    server = MCPServer(tools=tools)
    init_resp = asyncio.run(
        server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    )
    assert "result" in init_resp
    list_resp = asyncio.run(
        server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    )
    assert len(list_resp["result"]["tools"]) >= 3