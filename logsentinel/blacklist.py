"""
IP Blacklist / Reputation module for RocketLogAI.

Supports multiple free and paid providers.
Downloads lists on startup and refreshes daily.
Fast in-memory lookup for threat analysis.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Set

import requests

from .config import BlacklistConfig, BlacklistProvider

logger = logging.getLogger(__name__)

BLACKLIST_DIR = Path("data/blacklists")
BLACKLIST_DIR.mkdir(parents=True, exist_ok=True)


class IPBlacklist:
    def __init__(self, cfg: BlacklistConfig):
        self.cfg = cfg
        self.networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.ips: Set[str] = set()
        self.last_update: float = 0
        self.loaded = False

    def _get_cache_path(self, provider_name: str) -> Path:
        return BLACKLIST_DIR / f"{provider_name}.txt"

    def _should_refresh(self, provider: BlacklistProvider) -> bool:
        cache = self._get_cache_path(provider.name)
        if not cache.exists():
            return True
        age = time.time() - cache.stat().st_mtime
        return age > (provider.update_interval_hours * 3600)

    def _download(self, provider: BlacklistProvider) -> bool:
        if not provider.url:
            return False
        try:
            headers = {}
            if provider.api_key:
                headers["Key"] = provider.api_key  # AbuseIPDB style

            resp = requests.get(provider.url, headers=headers, timeout=30)
            resp.raise_for_status()

            cache_path = self._get_cache_path(provider.name)
            cache_path.write_text(resp.text, encoding="utf-8")
            logger.info("Downloaded blacklist %s (%d bytes)", provider.name, len(resp.text))
            return True
        except Exception as e:
            logger.warning("Failed to download blacklist %s: %s", provider.name, e)
            return False

    def load(self, force: bool = False):
        """Load all enabled providers into memory."""
        self.networks = []
        self.ips = set()

        for provider in self.cfg.providers:
            if not provider.enabled:
                continue

            cache = self._get_cache_path(provider.name)

            if force or self._should_refresh(provider):
                self._download(provider)

            if not cache.exists():
                continue

            try:
                content = cache.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        if "/" in line:
                            net = ipaddress.ip_network(line, strict=False)
                            self.networks.append(net)
                        else:
                            self.ips.add(line)
                    except ValueError:
                        continue
                logger.debug("Loaded blacklist %s: %d networks, %d exact IPs", 
                             provider.name, len([n for n in self.networks if n.version]), len(self.ips))
            except Exception as e:
                logger.warning("Error loading blacklist cache %s: %s", provider.name, e)

        self.loaded = True
        self.last_update = time.time()
        logger.info("IP Blacklist ready: %d networks + %d exact IPs loaded", len(self.networks), len(self.ips))

    def is_blacklisted(self, ip: str) -> bool:
        if not self.cfg.enabled or not self.loaded:
            return False
        try:
            ipa = ipaddress.ip_address(ip)
            if str(ipa) in self.ips:
                return True
            for net in self.networks:
                if ipa in net:
                    return True
        except ValueError:
            return False
        return False

    def refresh_if_needed(self):
        """Call on startup and periodically."""
        if not self.cfg.enabled:
            return
        if time.time() - self.last_update > 3600:  # check at most hourly
            self.load(force=False)


# Singleton
_blacklist: IPBlacklist | None = None


def get_blacklist(cfg: BlacklistConfig | None = None) -> IPBlacklist:
    global _blacklist
    if _blacklist is None:
        if cfg is None:
            cfg = BlacklistConfig()
        _blacklist = IPBlacklist(cfg)
        _blacklist.load()
    return _blacklist