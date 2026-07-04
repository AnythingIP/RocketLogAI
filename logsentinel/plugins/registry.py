"""
Plugin registry — discover and load plugins.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

from .base import RocketPlugin

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Manage plugin lifecycle."""

    def __init__(self):
        self._plugins: dict[str, RocketPlugin] = {}
        self._context: dict[str, Any] = {}

    def set_context(self, **kwargs: Any) -> None:
        self._context.update(kwargs)

    async def load(self, plugin_class: type[RocketPlugin]) -> RocketPlugin:
        instance = plugin_class()
        await instance.on_load(self._context)
        self._plugins[instance.name] = instance
        logger.info("Loaded plugin: %s v%s", instance.name, instance.version)
        return instance

    async def load_module(self, module_path: str, class_name: str) -> RocketPlugin | None:
        try:
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            if not issubclass(cls, RocketPlugin):
                raise TypeError(f"{class_name} is not a RocketPlugin")
            return await self.load(cls)
        except Exception as exc:
            logger.error("Failed to load plugin %s.%s: %s", module_path, class_name, exc)
            return None

    async def unload(self, name: str) -> bool:
        plugin = self._plugins.pop(name, None)
        if plugin:
            await plugin.on_unload()
            return True
        return False

    def list_plugins(self) -> list[dict[str, str]]:
        return [
            {"name": p.name, "version": p.version, "description": p.description}
            for p in self._plugins.values()
        ]

    def get_all_tools(self) -> list[dict[str, Any]]:
        tools = []
        for plugin in self._plugins.values():
            tools.extend(plugin.get_tools())
        return tools