"""
Wazuh-style HIDS integration — alert export and agent status.
"""

from __future__ import annotations

import json
import time
from typing import Any

import requests


class WazuhIntegration:
    def __init__(self, manager_url: str, user: str = "", password: str = "", verify_ssl: bool = True):
        self.manager_url = manager_url.rstrip("/")
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self._token: str | None = None

    def _auth(self) -> dict[str, str]:
        if not self._token and self.user:
            try:
                r = requests.post(
                    f"{self.manager_url}/security/user/authenticate",
                    auth=(self.user, self.password),
                    verify=self.verify_ssl,
                    timeout=10,
                )
                if r.status_code == 200:
                    self._token = r.json().get("data", {}).get("token", "")
            except Exception:
                pass
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    def test_connection(self) -> dict[str, Any]:
        try:
            r = requests.get(
                f"{self.manager_url}/",
                headers=self._auth(),
                verify=self.verify_ssl,
                timeout=10,
            )
            return {"status": "ok" if r.status_code < 500 else "error", "code": r.status_code}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}

    def export_alert(self, threat: dict[str, Any]) -> dict[str, Any]:
        """Format RocketLogAI threat as Wazuh-compatible alert JSON."""
        alert = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "rule": {
                "level": {"low": 3, "medium": 7, "high": 12, "critical": 15}.get(threat.get("severity", "medium"), 7),
                "description": threat.get("description", ""),
                "id": threat.get("id", 0),
            },
            "agent": {"name": threat.get("hostname", "rocketlogai")},
            "data": threat,
            "source": "rocketlogai",
        }
        return {"alert": alert, "json": json.dumps(alert)}

    def list_agents(self) -> dict[str, Any]:
        try:
            r = requests.get(
                f"{self.manager_url}/agents",
                headers=self._auth(),
                verify=self.verify_ssl,
                timeout=15,
            )
            if r.status_code == 200:
                return {"status": "ok", "agents": r.json()}
            return {"status": "error", "code": r.status_code}
        except Exception as exc:
            return {"status": "error", "message": str(exc)}