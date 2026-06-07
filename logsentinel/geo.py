"""
IP Geolocation for LogSentinel.

Primary: Fully offline using MaxMind GeoLite2 City database.
Fallback: Online lookup (only for public IPs) when the local database doesn't have the IP.

Private IPs (10/8, 172.16/12, 192.168/16, loopback, link-local) are never looked up online.

Results are always cached in the local database for future use.
"""

from __future__ import annotations

import logging
import os
import platform
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_IS_WINDOWS = platform.system() == "Windows"
_IS_MAC = platform.system() == "Darwin"

def _build_geo_search_paths() -> list[Path]:
    """Build an OS-aware list of places to look for GeoLite2-City.mmdb.
    This makes moving the server between Windows/Linux/Mac much more reliable.
    """
    paths: list[Path] = []

    # Highest priority: explicit current working directory + data/ (works great for /Volumes/logsentinel style deploys)
    paths.append(Path.cwd() / "GeoLite2-City.mmdb")
    paths.append(Path.cwd() / "data" / "GeoLite2-City.mmdb")

    # User's preferred volume (very common for this user)
    if _IS_MAC:
        paths.extend([
            Path("/Volumes/logsentinel/GeoLite2-City.mmdb"),
            Path("/Volumes/logsentinel/data/GeoLite2-City.mmdb"),
        ])

    # Home directory locations
    paths.append(Path.home() / ".logsentinel" / "GeoLite2-City.mmdb")
    if _IS_WINDOWS:
        paths.append(Path.home() / "AppData" / "Local" / "logsentinel" / "GeoLite2-City.mmdb")
    else:
        paths.append(Path("/etc/logsentinel/GeoLite2-City.mmdb"))
        paths.append(Path("/usr/local/share/GeoIP/GeoLite2-City.mmdb"))

    # Windows-specific locations (only add on Windows or when explicitly present)
    if _IS_WINDOWS:
        paths.extend([
            Path("C:/ProgramData/logsentinel/GeoLite2-City.mmdb"),
            Path("D:/logsentinel/GeoLite2-City.mmdb"),
        ])
    else:
        # Still check common Windows paths in case someone copied config from Windows
        paths.extend([
            Path("C:/ProgramData/logsentinel/GeoLite2-City.mmdb"),
            Path("D:/logsentinel/GeoLite2-City.mmdb"),
        ])

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for p in paths:
        sp = str(p)
        if sp not in seen:
            seen.add(sp)
            deduped.append(p)
    return deduped


# Build once at import time
DEFAULT_GEO_DB_PATHS = _build_geo_search_paths()

# Extra aggressive discovery for the specific volume the user runs from
VOLUME_LOG_SENTINEL_PATHS = [
    Path("/Volumes/logsentinel/GeoLite2-City.mmdb"),
    Path("/Volumes/logsentinel/data/GeoLite2-City.mmdb"),
]


# =============================================================================
# PLUGGABLE GEO PROVIDERS (new multi-source architecture)
# =============================================================================

class GeoProvider:
    """Base class for any geo source (offline or paid online services)."""
    name: str = "base"

    def enrich(self, ip: str) -> dict[str, Any] | None:
        """Return standardized geo dict or None."""
        raise NotImplementedError

    @property
    def available(self) -> bool:
        return True


class MaxMindProvider(GeoProvider):
    """MaxMind GeoLite2 / GeoIP2 provider (offline, high quality)."""
    name = "maxmind"

    def __init__(self, db_path: str | Path | None = None):
        self._reader = None
        self._db_path = None
        self._load(db_path)

    def _load(self, db_path: str | Path | None):
        if not db_path:
            for p in DEFAULT_GEO_DB_PATHS:
                if self._try_load(p):
                    break
        else:
            self._try_load(Path(db_path))

    def _try_load(self, path: Path) -> bool:
        if not path.exists():
            return False
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(path))
            self._db_path = str(path)
            logger.info("MaxMind geo provider loaded: %s", path)
            return True
        except Exception as e:
            logger.debug("Failed to load MaxMind at %s: %s", path, e)
            return False

    @property
    def available(self) -> bool:
        return self._reader is not None

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if not self.available or self._is_private_ip(ip):
            return None
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
            return None

    def _is_private_ip(self, ip: str) -> bool:
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except Exception:
            return ip.startswith(("10.", "192.168.", "172.16.", "127."))


class IPInfoProvider(GeoProvider):
    """ipinfo.io provider (excellent paid + good free tier with token)."""
    name = "ipinfo"

    def __init__(self, token: str = ""):
        self.token = token or os.environ.get("IPINFO_TOKEN", "")

    @property
    def available(self) -> bool:
        return bool(self.token)

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if not self.available:
            return None
        try:
            import requests
            url = f"https://ipinfo.io/{ip}/json?token={self.token}"
            r = requests.get(url, timeout=5)
            if r.status_code != 200:
                return None
            j = r.json()
            if "loc" in j:
                lat, lon = j["loc"].split(",")
                return {
                    "ip": ip,
                    "country": j.get("country"),
                    "city": j.get("city"),
                    "lat": float(lat),
                    "lon": float(lon),
                    "accuracy": None,
                    "source": "ipinfo",
                    "org": j.get("org"),
                }
        except Exception:
            pass
        return None


class IPApiProvider(GeoProvider):
    """ip-api.com (free, no key, good for fallback)."""
    name = "ipapi"

    def enrich(self, ip: str) -> dict[str, Any] | None:
        try:
            import requests
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,query"
            r = requests.get(url, timeout=5)
            j = r.json()
            if j.get("status") != "success":
                return None
            return {
                "ip": ip,
                "country": j.get("country"),
                "city": j.get("city"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
                "accuracy": None,
                "source": "ip-api.com",
            }
        except Exception:
            return None


class GenericHTTPGeoProvider(GeoProvider):
    """
    Easy extension point for any paid geo API.
    Example config:
      - type: "generic_http"
        url_template: "https://api.example.com/{ip}?key=YOURKEY"
        response_mapping:
          country: "country"
          city: "city"
          lat: "location.lat"
          lon: "location.lon"
    """
    name = "generic_http"

    def __init__(self, url_template: str = "", response_mapping: dict = None, **kwargs):
        self.url_template = url_template
        self.mapping = response_mapping or {"country": "country", "city": "city", "lat": "lat", "lon": "lon"}

    def enrich(self, ip: str) -> dict[str, Any] | None:
        if not self.url_template:
            return None
        try:
            import requests
            url = self.url_template.format(ip=ip)
            r = requests.get(url, timeout=6)
            if r.status_code != 200:
                return None
            j = r.json()

            def get_nested(d, path):
                for key in path.split('.'):
                    if isinstance(d, dict):
                        d = d.get(key)
                    else:
                        return None
                return d

            return {
                "ip": ip,
                "country": get_nested(j, self.mapping.get("country", "country")),
                "city": get_nested(j, self.mapping.get("city", "city")),
                "lat": get_nested(j, self.mapping.get("lat", "lat")),
                "lon": get_nested(j, self.mapping.get("lon", "lon")),
                "accuracy": None,
                "source": "custom_http",
            }
        except Exception:
            return None


# =============================================================================
# MULTI-SOURCE ENRICHER
# =============================================================================

class MultiGeoEnricher:
    """
    Supports multiple geo sources working together.
    Tries providers in priority order and applies merge strategy.
    """

    def __init__(self, providers: list[GeoProvider], merge_strategy: str = "first_success"):
        self.providers = sorted(providers, key=lambda p: getattr(p, 'priority', 10))
        self.merge_strategy = merge_strategy

    @property
    def available(self) -> bool:
        return any(p.available for p in self.providers)

    def enrich(self, ip: str | None) -> dict[str, Any] | None:
        if not ip:
            return None

        # Never enrich private IPs
        try:
            import ipaddress
            if ipaddress.ip_address(ip).is_private:
                return {"ip": ip, "country": None, "city": None, "source": "private_ip", "sources": ["private_ip"]}
        except Exception:
            pass

        results = []
        for provider in self.providers:
            if not provider.available:
                continue
            data = provider.enrich(ip)
            if data:
                data["source"] = getattr(provider, "name", provider.__class__.__name__.lower().replace("provider", ""))
                results.append(data)
                if self.merge_strategy == "first_success":
                    data["sources"] = [data["source"]]
                    return data

        if not results:
            return None

        if self.merge_strategy == "aggregate":
            # Merge best fields from all providers, track all sources
            merged = {"ip": ip, "source": "multi", "sources": []}
            for r in results:
                merged["sources"].append(r["source"])
                for k, v in r.items():
                    if k not in ("source", "sources") and (k not in merged or not merged.get(k)):
                        merged[k] = v
            return merged

        # Default: return the first (highest priority) successful result
        return results[0]

    def _online_enrich(self, ip: str) -> dict[str, Any] | None:
        """
        Online geo lookup with preference for ipinfo.io (better data & higher limits with free token).

        Order:
        1. ipinfo.io (if IPINFO_TOKEN env var is set)
        2. ip-api.com (free, no token required)

        Only called for public IPs. Result is cached by the caller.
        """
        try:
            import requests
        except ImportError:
            logger.warning(
                "Online geo lookup requested but 'requests' package is not installed. "
                "Install with: pip install 'logsentinel[web]' or pip install requests"
            )
            return None

        token = os.environ.get("IPINFO_TOKEN")

        # Prefer ipinfo.io when token is available (much better free tier)
        if token:
            try:
                url = f"https://ipinfo.io/{ip}/json?token={token}"
                r = requests.get(url, timeout=6)
                if r.status_code == 200:
                    j = r.json()
                    if "loc" in j:
                        lat, lon = j["loc"].split(",")
                        return {
                            "ip": ip,
                            "country": j.get("country"),
                            "city": j.get("city"),
                            "lat": float(lat),
                            "lon": float(lon),
                            "accuracy": None,
                            "source": "ipinfo.io",
                        }
            except Exception as e:
                logger.debug("ipinfo.io lookup failed for %s: %s", ip, e)

        # Fallback to ip-api.com (no token needed)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,city,lat,lon,query"
            r = requests.get(url, timeout=6)
            if r.status_code != 200:
                return None

            j = r.json()
            if j.get("status") != "success":
                return None

            return {
                "ip": ip,
                "country": j.get("country"),
                "city": j.get("city"),
                "lat": j.get("lat"),
                "lon": j.get("lon"),
                "accuracy": None,
                "source": "ip-api.com",
            }
        except Exception as e:
            logger.debug("ip-api.com lookup failed for %s: %s", ip, e)
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

    # Note: reload() and self_heal() for legacy single-GeoEnricher were removed here
    # because this class is now MultiGeoEnricher. The multi-provider version does not
    # use the old _reader / _try_load pattern.


# =============================================================================
# PUBLIC API (backward compatible + new multi-source)
# =============================================================================

_geo_enricher = None


def _build_multi_enricher(cfg=None) -> "MultiGeoEnricher":
    """Builds the new multi-provider enricher from config."""
    from .config import get_config  # avoid circular import

    if cfg is None:
        try:
            cfg = get_config()
        except Exception:
            cfg = None

    providers = []

    if cfg and cfg.geo and cfg.geo.providers:
        for pcfg in cfg.geo.providers:
            if not pcfg.enabled:
                continue
            if pcfg.type == "maxmind":
                providers.append(MaxMindProvider(pcfg.path or None))
            elif pcfg.type == "ipinfo":
                providers.append(IPInfoProvider(pcfg.token))
            elif pcfg.type == "ipapi":
                providers.append(IPApiProvider())
    else:
        # Legacy fallback: use old single MaxMind behavior
        providers.append(MaxMindProvider())

    strategy = "first_success"
    if cfg and cfg.geo:
        strategy = cfg.geo.merge_strategy or strategy

    return MultiGeoEnricher(providers, strategy)


def get_geo_enricher(custom_path: str | Path | None = None, *, force_reload: bool = False):
    """
    Returns a geo enricher.
    - If new multi-provider config is present → returns MultiGeoEnricher
    - Otherwise uses MaxMindProvider (legacy single mmdb_path or auto)
    """
    global _geo_enricher
    if force_reload or _geo_enricher is None:
        try:
            from .config import get_config
            cfg = get_config()
            if cfg and cfg.geo and cfg.geo.providers:
                _geo_enricher = _build_multi_enricher(cfg)
                return _geo_enricher
        except Exception:
            pass

        # Legacy path - use new MaxMindProvider for backward compat
        _geo_enricher = MultiGeoEnricher([MaxMindProvider(custom_path)])
    return _geo_enricher


def force_reload_geo(custom_path: str | Path | None = None):
    global _geo_enricher
    _geo_enricher = None
    return get_geo_enricher(custom_path, force_reload=True)
