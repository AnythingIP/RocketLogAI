"""Remote agents — safe install, sandboxed control, migration."""

from .manager import AgentManager
from .control import RemoteControl

__all__ = ["AgentManager", "RemoteControl"]