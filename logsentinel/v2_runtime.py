"""
RocketLogAI v2 runtime — wires all ecosystem components together.
"""

from __future__ import annotations

import logging
from typing import Any

from .agents.manager import AgentManager
from .audit.logger import AuditLogger
from .brain.orchestrator import AIOrchestrator
from .config import Config
from .mcp.server import MCPServer
from .mcp.tools import build_default_tools
from .mobile.api import MobileAPI
from .observability.metrics import MetricsRegistry
from .plugins.registry import PluginRegistry
from .remediate.engine import RemediationEngine
from .shield.av_scanner import AVScanner
from .shield.modes import ShieldConfig
from .shield.parental import ParentalControls
from .shield.waf import WAFEngine
from .ueba.detector import UEBADetector
from .ueba.reports import UEBAReportGenerator

logger = logging.getLogger(__name__)


class V2Runtime:
    """Singleton-style runtime context for v2 ecosystem."""

    def __init__(self, cfg: Config, storage: Any = None):
        self.cfg = cfg
        self.storage = storage
        data_dir = "./data"

        self.metrics = MetricsRegistry()
        self.audit = AuditLogger(db_path=f"{data_dir}/audit/audit.db")
        self.brain = AIOrchestrator(data_dir=f"{data_dir}/brain")
        self.remediate = RemediationEngine(cfg, storage=storage)
        self.agents = AgentManager(db_path=f"{data_dir}/agents/agents.db")
        self.mobile = MobileAPI(brain=self.brain, agents=self.agents)
        self.ueba = UEBADetector()
        self.ueba_reports = UEBAReportGenerator()
        self.plugins = PluginRegistry()
        self.plugins.set_context(cfg=cfg, storage=storage, brain=self.brain)

        shield_raw = getattr(cfg, "shield", None)
        if shield_raw:
            if isinstance(shield_raw, ShieldConfig):
                shield_cfg = shield_raw
            else:
                raw = shield_raw.__dict__ if hasattr(shield_raw, "__dict__") else {}
                shield_cfg = ShieldConfig.from_dict({
                    "enabled": getattr(shield_raw, "enabled", raw.get("enabled", False)),
                    "mode": getattr(shield_raw, "mode", raw.get("mode", "disabled")),
                    "block_mode": getattr(shield_raw, "block_mode", raw.get("block_mode", "detect")),
                })
        else:
            shield_cfg = ShieldConfig()

        self.shield_config = shield_cfg
        self.waf = WAFEngine(block_mode=shield_cfg.block_mode)
        self.av = AVScanner()
        self.parental = ParentalControls()

        tools = build_default_tools(storage=storage, brain=self.brain)
        self.mcp = MCPServer(version="2.0.0", tools=tools)

    def observe_log(self, log: dict[str, Any]) -> None:
        entity = log.get("hostname") or log.get("source_ip") or "unknown"
        self.ueba.observe(entity, "host", log)
        self.metrics.inc("logs_ingested_total")
        sev = log.get("severity", "low")
        if sev in ("high", "critical"):
            self.metrics.inc("logs_high_severity_total", labels={"severity": sev})

    def status(self) -> dict[str, Any]:
        return {
            "version": "2.0.0",
            "brain": self.brain.status(),
            "remediate": self.remediate.get_status(),
            "shield": {
                "enabled": self.shield_config.enabled,
                "mode": self.shield_config.mode.value,
                "waf": self.waf.status(),
                "av": self.av.status(),
                "parental": self.parental.status(),
            },
            "agents": {"count": len(self.agents.list_agents())},
            "mobile": self.mobile.status(),
            "plugins": self.plugins.list_plugins(),
            "metrics": self.metrics.snapshot(),
        }


_runtime: V2Runtime | None = None


def get_v2_runtime(cfg: Config | None = None, storage: Any = None) -> V2Runtime:
    global _runtime
    if _runtime is None:
        if cfg is None:
            from .config import Config as C
            cfg = C.load()
        _runtime = V2Runtime(cfg, storage)
    elif storage and _runtime.storage is None:
        _runtime.storage = storage
    return _runtime


def reset_v2_runtime() -> None:
    global _runtime
    _runtime = None