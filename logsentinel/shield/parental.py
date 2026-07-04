"""
Parental controls — time-based and category-based filtering.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ParentalProfile:
    name: str
    device_macs: list[str] = field(default_factory=list)
    blocked_categories: list[str] = field(default_factory=lambda: ["adult", "gambling", "malware"])
    blocked_domains: list[str] = field(default_factory=list)
    allowed_hours: tuple[int, int] = (6, 22)  # 6am - 10pm
    enabled: bool = True


CATEGORY_DOMAINS = {
    "adult": ["pornhub.com", "xvideos.com"],
    "gambling": ["bet365.com", "draftkings.com"],
    "social": ["tiktok.com", "snapchat.com"],
    "gaming": ["steam.com", "epicgames.com"],
}


class ParentalControls:
    """Parental control engine for RocketShield."""

    def __init__(self, profiles: list[ParentalProfile] | None = None):
        self.profiles = profiles or []

    def add_profile(self, profile: ParentalProfile) -> None:
        self.profiles.append(profile)

    def _profile_for_mac(self, mac: str) -> ParentalProfile | None:
        mac = mac.lower().replace("-", ":")
        for p in self.profiles:
            if mac in [m.lower().replace("-", ":") for m in p.device_macs]:
                return p
        return None

    def check_access(self, mac: str, domain: str, category: str = "") -> dict[str, Any]:
        profile = self._profile_for_mac(mac)
        if not profile or not profile.enabled:
            return {"allowed": True, "reason": "no profile"}

        hour = datetime.now().hour
        start, end = profile.allowed_hours
        if not (start <= hour < end):
            return {"allowed": False, "reason": "outside allowed hours", "profile": profile.name}

        domain = domain.lower()
        for blocked in profile.blocked_domains:
            if blocked.lower() in domain:
                return {"allowed": False, "reason": f"blocked domain: {blocked}", "profile": profile.name}

        for cat in profile.blocked_categories:
            if category == cat or any(d in domain for d in CATEGORY_DOMAINS.get(cat, [])):
                return {"allowed": False, "reason": f"blocked category: {cat}", "profile": profile.name}

        return {"allowed": True, "profile": profile.name}

    def status(self) -> dict[str, Any]:
        return {"profiles": len(self.profiles), "active": sum(1 for p in self.profiles if p.enabled)}