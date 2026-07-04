"""Plugin system for extensible integrations."""

from .registry import PluginRegistry
from .base import RocketPlugin

__all__ = ["PluginRegistry", "RocketPlugin"]