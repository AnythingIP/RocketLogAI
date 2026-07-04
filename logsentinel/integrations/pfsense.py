"""
pfSense integration — syslog forwarding and API blocklist sync.
"""

from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


class PfSenseIntegration:
    def __init__(self, host: str, api_key: str = "", verify_ssl: bool = True):
        self.host = host.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def test_connection(self) -> dict[str, Any]:
        try:
            r = requests.get(f"{self.host}/api/v1/system/version", headers=self._headers(), verify=self.verify_ssl, timeout=10)
            if r.status_code == 200:
                return {"status": "ok", "version": r.json()}
            return {"status": "error", "code": r.status_code}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def block_ip(self, ip: str, description: str = "RocketLogAI block") -> dict[str, Any]:
        payload = {"type": "block", "address": ip, "descr": description}
        try:
            r = requests.post(
                f"{self.host}/api/v1/firewall/alias",
                json=payload,
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=15,
            )
            return {"status": "submitted", "ip": ip, "response_code": r.status_code}
        except Exception as exc:
            logger.exception("pfSense block_ip failed")
            return {"status": "error", "message": str(exc)}

    def syslog_config(self, target_host: str, port: int = 5140, protocol: str = "udp") -> dict[str, Any]:
        return {
            "status": "config_template",
            "instructions": f"Configure pfSense Status > System Logs > Settings to forward to {target_host}:{port} ({protocol})",
            "target": f"{target_host}:{port}",
            "protocol": protocol,
        }