"""
RocketShield deployment modes — inline and port mirroring/SPAN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ShieldMode(str, Enum):
    INLINE = "inline"
    SPAN = "span"
    TAP = "tap"
    DISABLED = "disabled"


@dataclass
class ShieldConfig:
    enabled: bool = False
    mode: ShieldMode = ShieldMode.DISABLED
    interface: str = ""
    mirror_interface: str = ""
    inline_bridge: str = ""
    decrypt_tls: bool = False
    ca_cert_path: str = ""
    waf_enabled: bool = True
    av_enabled: bool = True
    parental_enabled: bool = False
    block_mode: str = "detect"  # detect | block
    rules_path: str = "./data/shield/rules"
    max_connections: int = 10000
    log_decrypted: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> ShieldConfig:
        mode_str = raw.get("mode", "disabled")
        try:
            mode = ShieldMode(mode_str)
        except ValueError:
            mode = ShieldMode.DISABLED
        return cls(
            enabled=raw.get("enabled", False),
            mode=mode,
            interface=raw.get("interface", ""),
            mirror_interface=raw.get("mirror_interface", ""),
            inline_bridge=raw.get("inline_bridge", ""),
            decrypt_tls=raw.get("decrypt_tls", False),
            ca_cert_path=raw.get("ca_cert_path", ""),
            waf_enabled=raw.get("waf_enabled", True),
            av_enabled=raw.get("av_enabled", True),
            parental_enabled=raw.get("parental_enabled", False),
            block_mode=raw.get("block_mode", "detect"),
            rules_path=raw.get("rules_path", "./data/shield/rules"),
            max_connections=raw.get("max_connections", 10000),
            log_decrypted=raw.get("log_decrypted", False),
            extra=raw.get("extra", {}),
        )