"""
Mobile API helpers — voice/text assistant, remote control, agent pairing.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

from .sync import SyncManager


class MobileAPI:
    """Server-side mobile API coordinator."""

    def __init__(self, sync: SyncManager | None = None, brain: Any = None, agents: Any = None):
        self.sync = sync or SyncManager()
        self.brain = brain
        self.agents = agents
        self._pairing_codes: dict[str, dict[str, Any]] = {}

    def generate_pairing_qr(self, user_id: str = "") -> dict[str, Any]:
        code = secrets.token_urlsafe(8).upper()[:8]
        self._pairing_codes[code] = {
            "user_id": user_id,
            "created_at": time.time(),
            "expires_at": time.time() + 300,
            "used": False,
        }
        return {
            "code": code,
            "qr_payload": f"rocketlogai://pair?code={code}",
            "expires_in": 300,
        }

    def pair_device(self, code: str, device_id: str, platform: str = "unknown") -> dict[str, Any]:
        entry = self._pairing_codes.get(code.upper())
        if not entry:
            return {"error": "invalid code"}
        if entry["used"] or time.time() > entry["expires_at"]:
            return {"error": "code expired or used"}
        entry["used"] = True
        token = secrets.token_urlsafe(32)
        return {
            "device_id": device_id,
            "platform": platform,
            "api_token": f"rlm_{token}",
            "user_id": entry.get("user_id", ""),
        }

    async def assistant_query(
        self,
        device_id: str,
        query: str,
        voice: bool = False,
        llm_call: Any = None,
    ) -> dict[str, Any]:
        session_id = f"mobile:{device_id}"
        if self.brain:
            result = await self.brain.ask(session_id, query, llm_call=llm_call)
            self.sync.push(device_id, [{"type": "assistant_turn", "payload": result}])
            return {**result, "voice": voice}
        return {"response": "Brain not configured", "device_id": device_id}

    async def remote_control(self, device_id: str, command: str, target_agent: str = "") -> dict[str, Any]:
        if not self.agents:
            return {"error": "agent manager not configured"}
        return await self.agents.execute_command(target_agent or device_id, command)

    def status(self) -> dict[str, Any]:
        return {
            "pairing_codes_active": sum(
                1 for c in self._pairing_codes.values()
                if not c["used"] and time.time() < c["expires_at"]
            ),
        }