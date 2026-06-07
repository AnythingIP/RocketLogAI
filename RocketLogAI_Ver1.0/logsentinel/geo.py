"""
Fully offline IP geolocation for LogSentinel.

Uses MaxMind GeoLite2 City database if present (free to download).
Everything is graceful: if the database or the geoip2 library is missing,
all calls return None / safe defaults. No network calls at runtime.

Recommended setup (one time):
    1. Sign up for free at https://www.maxmind.com (GeoLite2 account)
    2. Download GeoLite2-City.mmdb
    3. Place it in one of these locations:
       - ~/.logsentinel/GeoLite2-City.mmdb
       - ./data/GeoLite2-City.mmdb   (relative to your db)
       - /etc/logsentinel/GeoLite2-City.mmdb

The enricher will auto-detect and use it. No config change needed.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Common locations we check (in order)
DEFAULT_GEO_DB_PATHS = [
    Path.home() / ".logsentinel" / "GeoLite2-City.mmdb",
    Path.cwd() / "GeoLite2-City.mmdb",          # project root (common when running from /Volumes/logsentinel etc.)
    Path.cwd() / "data" / "GeoLite2-City.mmdb",
    # Explicit support for the user's /Volumes/logsentinel setup
    Path("/Volumes/logsentinel/GeoLite2-City.mmdb"),
    Path("/Volumes/logsentinel/data/GeoLite2-City.mmdb"),
    # Windows common locations
    Path("C:/ProgramData/logsentinel/GeoLite2-City.mmdb"),
    Path("D:/logsentinel/GeoLite2-City.mmdb"),
    Path.home() / "AppData" / "Local" / "logsentinel" / "GeoLite2-City.mmdb",
    Path("/etc/logsentinel/GeoLite2-City.mmdb"),
    Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"),
]

# Extra aggressive discovery for the specific volume the user runs from
VOLUME_LOG_SENTINEL_PATHS = [
    Path("/Volumes/logsentinel/GeoLite2-City.mmdb"),
    Path("/Volumes/logsentinel/data/GeoLite2-City.mmdb"),
]


class OfflineGeoEnricher:
    """
    Fully offline IP -> geo enrichment.
    """

    def __init__(self, custom_db_path: str | Path | None = None):
        self._reader = None
        self._db_path = None
        self._tried = False

        if custom_db_path:
            self._try_load(Path(custom_db_path))
        else:
            for p in DEFAULT_GEO_DB_PATHS:
                if self._try_load(p):
                    break

    def _try_load(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            import geoip2.database  # type: ignore

            self._reader = geoip2.database.Reader(str(path))
            self._db_path = str(path)
            logger.info("Offline geo enabled using %s", path)
            return True
        except ImportError:
            logger.warning(
                "geoip2 package not installed. Run: pip install 'logsentinel[web]' or pip install geoip2"
            )
            return False
        except Exception as e:
            logger.warning("Failed to load GeoLite2 database at %s: %s", path, e)
            return False

    @property
    def available(self) -> bool:
        return self._reader is not None

    @property
    def db_path(self) -> str | None:
        return self._db_path

    def enrich(self, ip: str | None) -> dict[str, Any] | None:
        """
        Return geo dict or None.

        Keys: ip, country, city, lat, lon, accuracy, source
        """
        if not ip or not self.available:
            return None

        # Quick private IP check (no point looking up)
        if self._is_private_ip(ip):
            return {
                "ip": ip,
                "country": None,
                "city": None,
                "lat": None,
                "lon": None,
                "accuracy": None,
                "source": "private_ip",
            }

        try:
            resp = self._reader.city(ip)
            return {
                "ip": ip,
                "country": resp.country.name,
                "city": resp.city.name,
                "lat": resp.location.latitude,
                "lon": resp.location.longitude,
                "accuracy": resp.location.accuracy_radius,
                "source": "maxmind",
            }
        except Exception:
            # IP not in DB or other error — return nothing
            return None

    def _is_private_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            ipa = ipaddress.ip_address(ip)
            return ipa.is_private or ipa.is_loopback or ipa.is_link_local
        except Exception:
            # If ipaddress not available or weird IP, treat as non-private
            return ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                                  "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                                  "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                                  "172.29.", "172.30.", "172.31.", "127.", "169.254."))

    def reload(self, custom_path: str | Path | None = None) -> bool:
        """Attempt to (re)load the GeoLite2 database. Returns True if a reader is now available."""
        self._reader = None
        self._db_path = None

        candidates = []
        if custom_path:
            candidates.append(Path(custom_path))
        # Always be very aggressive for the /Volumes/logsentinel case
        candidates.extend(VOLUME_LOG_SENTINEL_PATHS)
        candidates.extend(DEFAULT_GEO_DB_PATHS)

        # Dedup while preserving order
        seen = set()
        for p in candidates:
            if str(p) not in seen:
                seen.add(str(p))
                if self._try_load(p):
                    return True
        return self.available

    def self_heal(self) -> bool:
        """If we are currently unavailable, try very hard one more time to find a DB (no-op if already loaded)."""
        if self.available:
            return True
        return self.reload()


# Singleton-ish helper used by analyzer and web
_geo_enricher: OfflineGeoEnricher | None = None


def get_geo_enricher(custom_path: str | Path | None = None, *, force_reload: bool = False) -> OfflineGeoEnricher:
    global _geo_enricher
    if force_reload or _geo_enricher is None:
        _geo_enricher = OfflineGeoEnricher(custom_path)
        # Extra aggressive pass for the user's /Volumes/logsentinel environment
        if not _geo_enricher.available:
            _geo_enricher.reload()
    elif custom_path and not _geo_enricher.available:
        _geo_enricher.reload(custom_path)
    return _geo_enricher


def force_reload_geo(custom_path: str | Path | None = None) -> OfflineGeoEnricher:
    """Public helper to force the singleton to drop and re-scan for the database.
    Call this from the web UI or after a user places a new .mmdb file.
    """
    global _geo_enricher
    _geo_enricher = None
    return get_geo_enricher(custom_path, force_reload=True)
