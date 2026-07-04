"""
Base plugin interface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RocketPlugin(ABC):
    """Base class for RocketLogAI plugins."""

    name: str = "unnamed"
    version: str = "1.0.0"
    description: str = ""

    @abstractmethod
    async def on_load(self, context: dict[str, Any]) -> None:
        """Called when plugin is loaded."""

    @abstractmethod
    async def on_unload(self) -> None:
        """Called when plugin is unloaded."""

    def get_tools(self) -> list[dict[str, Any]]:
        """Optional MCP tools exposed by this plugin."""
        return []