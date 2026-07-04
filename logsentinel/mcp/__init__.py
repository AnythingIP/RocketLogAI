"""MCP server — Graylog/Zabbix-style tool exposure for external AI clients."""

from .server import MCPServer
from .tools import build_default_tools

__all__ = ["MCPServer", "build_default_tools"]