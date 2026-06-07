"""
Deep, privacy-first Home Assistant integration for RocketLogAI.

Fully local. No cloud. Uses long-lived access token.

Capabilities:
- Pull device registry + states (for IP/MAC/entity matching)
- Enrich threats with "this came from your living room Hue bridge"
- Trigger rich alerting on verified major threats:
    * persistent_notification
    * custom event (automations can react)
    * update/create sensors (logsentinel_open_threats, logsentinel_last_threat)  # sensor names kept for backward compat with existing HA automations
    * call any notify.* or script.* you configure
- Manual "Trigger HA Alert" from the UI
- Cache everything locally

Config example:
home_assistant:
  enabled: true
  url: "http://homeassistant.local:8123"
  token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  verify_ssl: true
  auto_enrich: true
  trigger_on_statuses: ["verified_threat"]
  notify_services: ["notify.mobile_app_yourphone", "notify.telegram"]
  custom_event: "logsentinel.major_threat"
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class HomeAssistantClient:
    """
    Deep bidirectional(ish) integration with a local Home Assistant instance.
    """

    def __init__(
        self,
        url: str,
        token: str,
        verify_ssl: bool = True,
        timeout: int = 15,
    ):
        self.base_url = url.rstrip("/")
        self.token = token
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        self._client = httpx.Client(
            verify=verify_ssl,
            timeout=timeout,
            headers=self._headers,
        )

    def is_available(self) -> bool:
        try:
            r = self._client.get(f"{self.base_url}/api/")
            return r.status_code == 200
        except Exception as e:
            logger.debug("HA connectivity check failed: %s", e)
            return False

    def get_device_registry(self) -> list[dict[str, Any]]:
        """Returns list of devices (best effort)."""
        try:
            # HA has /api/devices but it's not always exposed the same way.
            # We get states and also try the websocket-style config API if available.
            r = self._client.get(f"{self.base_url}/api/states")
            if r.status_code != 200:
                return []
            states = r.json()
            # We also try the newer /api/config/devices
            try:
                r2 = self._client.get(f"{self.base_url}/api/config/devices")
                if r2.status_code == 200:
                    return r2.json()
            except Exception:
                pass
            # Fallback: synthesize from states
            devices = {}
            for s in states:
                attrs = s.get("attributes", {})
                dev_id = attrs.get("device_id") or attrs.get("device")
                if dev_id and dev_id not in devices:
                    devices[dev_id] = {
                        "id": dev_id,
                        "name": attrs.get("friendly_name") or s.get("entity_id"),
                        "area": attrs.get("area"),
                        "entities": [],
                    }
            return list(devices.values())
        except Exception as e:
            logger.warning("Failed to pull HA device registry: %s", e)
            return []

    def get_states(self) -> list[dict[str, Any]]:
        try:
            r = self._client.get(f"{self.base_url}/api/states")
            if r.status_code == 200:
                return r.json()
            return []
        except Exception as e:
            logger.warning("HA get_states failed: %s", e)
            return []

    def find_device_for_ip_or_mac(self, ip: str | None = None, mac: str | None = None) -> dict[str, Any] | None:
        """
        Best effort matching against all states.
        Looks for ip, ipv4, mac, mac_address, host, etc. in attributes.
        """
        states = self.get_states()
        candidates = []

        for state in states:
            attrs = state.get("attributes", {}) or {}
            eid = state.get("entity_id", "")

            haystack = json.dumps(attrs).lower() + " " + eid.lower()

            match = False
            if ip and ip in haystack:
                match = True
            if mac and mac.replace(":", "").lower() in haystack.replace(":", ""):
                match = True

            if match:
                candidates.append({
                    "entity_id": eid,
                    "name": attrs.get("friendly_name") or eid,
                    "area": attrs.get("area") or attrs.get("area_id"),
                    "state": state.get("state"),
                    "attributes": attrs,
                })

        if not candidates:
            return None

        # Prefer devices that look like actual hardware
        for c in candidates:
            if any(x in c["entity_id"] for x in ("light.", "switch.", "sensor.", "binary_sensor.", "device_tracker.")):
                return c
        return candidates[0]

    # --- Alerting / Triggering ---

    def fire_event(self, event: str, data: dict[str, Any]) -> bool:
        try:
            r = self._client.post(
                f"{self.base_url}/api/events/{event}",
                json=data,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.warning("Failed to fire HA event %s: %s", event, e)
            return False

    def create_persistent_notification(self, message: str, title: str = "RocketLogAI Alert", notification_id: str | None = None) -> bool:
        try:
            payload = {"title": title, "message": message}
            if notification_id:
                payload["notification_id"] = notification_id
            r = self._client.post(
                f"{self.base_url}/api/services/persistent_notification/create",
                json=payload,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.warning("HA persistent_notification failed: %s", e)
            return False

    def update_sensor(self, entity_id: str, state: str, attributes: dict[str, Any]) -> bool:
        """Create or update a sensor.* entity from RocketLogAI."""
        try:
            payload = {
                "state": str(state),
                "attributes": attributes or {},
            }
            r = self._client.post(
                f"{self.base_url}/api/states/{entity_id}",
                json=payload,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.warning("HA sensor update failed for %s: %s", entity_id, e)
            return False

    def call_service(self, domain: str, service: str, data: dict[str, Any]) -> bool:
        try:
            r = self._client.post(
                f"{self.base_url}/api/services/{domain}/{service}",
                json=data,
            )
            return r.status_code in (200, 201)
        except Exception as e:
            logger.warning("HA service call %s.%s failed: %s", domain, service, e)
            return False

    def trigger_major_threat_alert(
        self,
        threat: dict[str, Any],
        notify_services: list[str] | None = None,
        custom_event: str = "logsentinel.major_threat",
    ) -> dict[str, Any]:
        """
        The "big red button" for a verified serious threat.
        Returns dict of what succeeded.
        """
        results = {"notification": False, "event": False, "sensors": False, "notify": []}

        summary = threat.get("description", "Unknown threat")
        severity = threat.get("severity", "high").upper()
        hostname = threat.get("hostname") or threat.get("appname") or "unknown host"
        threat_id = threat.get("id")

        message = (
            f"🚨 **{severity}** threat verified by RocketLogAI\n\n"
            f"**{summary}**\n\n"
            f"Host: {hostname}\n"
            f"Time: {threat.get('created_at', '')[:19]}\n"
            f"Threat ID: #{threat_id}"
        )

        # 1. Persistent notification in HA UI
        results["notification"] = self.create_persistent_notification(
            message,
            title=f"RocketLogAI • {severity} Alert",
            notification_id=f"logsentinel_threat_{threat_id}",
        )

        # 2. Fire rich custom event (your automations listen to this)
        event_data = {
            "threat_id": threat_id,
            "severity": threat.get("severity"),
            "description": summary,
            "hostname": hostname,
            "source_ip": threat.get("source_ip"),
            "recommended_action": threat.get("recommended_action"),
            "ha_device": threat.get("ha_device_name"),
            "ha_entity": threat.get("ha_entity_id"),
            "geo": {
                "country": threat.get("geo_country"),
                "city": threat.get("geo_city"),
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        results["event"] = self.fire_event(custom_event, event_data)

        # 3. Update sensors
        try:
            self.update_sensor(
                "sensor.logsentinel_last_threat",
                summary[:100],
                {
                    "threat_id": threat_id,
                    "severity": threat.get("severity"),
                    "hostname": hostname,
                    "source_ip": threat.get("source_ip"),
                    "geo_city": threat.get("geo_city"),
                    "ha_device": threat.get("ha_device_name"),
                    "last_triggered": datetime.now(timezone.utc).isoformat(),
                },
            )
            results["sensors"] = True
        except Exception:
            pass

        # 4. Notify mobile / telegram / etc.
        if notify_services:
            for svc in notify_services:
                if "." in svc:
                    domain, service = svc.split(".", 1)
                    ok = self.call_service(
                        domain,
                        service,
                        {"message": message, "title": f"RocketLogAI {severity} Alert"},
                    )
                    if ok:
                        results["notify"].append(svc)

        logger.info("HA major threat alert triggered for threat #%s -> %s", threat_id, results)
        return results


# Singleton factory
_ha_client: HomeAssistantClient | None = None


def get_ha_client(cfg: Any | None = None) -> HomeAssistantClient | None:
    """
    Factory that respects RocketLogAI Config.
    Accepts either the full config object or the home_assistant subsection directly
    (defensive against past call sites).
    """
    global _ha_client
    if _ha_client is not None:
        return _ha_client

    ha_cfg = None

    if cfg is None:
        return None

    # If they passed the full config object
    if getattr(cfg, "home_assistant", None):
        ha_cfg = cfg.home_assistant
    # If they passed the subsection directly (url + token present)
    elif getattr(cfg, "url", None) and getattr(cfg, "token", None):
        ha_cfg = cfg
    else:
        return None

    if not getattr(ha_cfg, "enabled", False):
        return None

    url = getattr(ha_cfg, "url", None)
    token = getattr(ha_cfg, "token", None)
    if not url or not token:
        logger.warning("Home Assistant enabled in config but url or token missing")
        return None

    try:
        client = HomeAssistantClient(
            url=url,
            token=token,
            verify_ssl=getattr(ha_cfg, "verify_ssl", True),
        )
        if client.is_available():
            _ha_client = client
            logger.info("Home Assistant integration connected: %s", url)
            return _ha_client
        else:
            logger.warning("Home Assistant at %s did not respond correctly", url)
            return None
    except Exception as e:
        logger.error("Failed to create HA client: %s", e)
        return None
