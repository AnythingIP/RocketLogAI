"""
OPNsense integration.
"""

from __future__ import annotations

from typing import Any

import requests


class OpnSenseIntegration:
    def __init__(self, host: str, api_key: str = "", api_secret: str = "", verify_ssl: bool = True):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.api_secret = api_secret
        self.verify_ssl = verify_ssl

    def test_connection(self) -> dict[str, Any]:
        try:
            r = requests.get(
                f"{self.host}/api/core/firmware/status",
                auth=(self.api_key, self.api_secret) if self.api_key else None,
                verify=self.verify_ssl,
                timeout=10,
            )
            return {"status": "ok" if r.status_code == 200 else "error", "code": r.status_code}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def block_ip(self, ip: str) -> dict[str, Any]:
        return {
            "status": "config_template",
            "ip": ip,
            "instructions": f"Add {ip} to OPNsense Firewall > Aliases > Blocklist, or use os-firewall plugin API",
        }

    def syslog_config(self, target_host: str, port: int = 5140) -> dict[str, Any]:
        return {
            "status": "config_template",
            "target": f"{target_host}:{port}",
            "instructions": "System > Settings > Logging / Targets — add remote syslog target",
        }