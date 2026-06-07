"""
MAC Address Vendor / Manufacturer Lookup for RocketLogAI.

Provides offline-capable device type identification (Phone, IoT, TV, NAS, Router, etc.)
using the official IEEE OUI database + smart category mapping + visual icons.

This helps:
- Quickly understand what kind of device an IP belongs to
- Detect when a device is behaving in ways atypical for its manufacturer
- Improve AI trust / risk decisions
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

MAC_VENDOR_DIR = Path("data/mac_vendors")
MAC_VENDOR_DIR.mkdir(parents=True, exist_ok=True)

# Primary reliable free source (community maintained, easy format)
OUI_URL = "https://raw.githubusercontent.com/arpalert/arpalert/master/mac-vendor.txt"
# Fallback official (sometimes returns 418 for bots)
OUI_FALLBACK = "https://standards-oui.ieee.org/oui/oui.txt"
CACHE_FILE = MAC_VENDOR_DIR / "oui.txt"
CACHE_AGE_SECONDS = 86400 * 7   # Refresh weekly (7 days)


class MacVendorLookup:
    def __init__(self):
        self.oui_map: Dict[str, str] = {}
        self.last_loaded = 0

    def _download_oui(self) -> bool:
        for url in [OUI_URL, OUI_FALLBACK]:
            try:
                resp = requests.get(url, timeout=30, headers={"User-Agent": "RocketLogAI/1.0"})
                resp.raise_for_status()
                CACHE_FILE.write_text(resp.text, encoding="utf-8")
                logger.info("Downloaded MAC vendor database from %s (%d bytes)", url, len(resp.text))
                return True
            except Exception as e:
                logger.warning("Failed to download from %s: %s", url, e)
        return False

    def _should_refresh(self) -> bool:
        if not CACHE_FILE.exists():
            return True
        age = time.time() - CACHE_FILE.stat().st_mtime
        return age > CACHE_AGE_SECONDS

    def load(self, force: bool = False):
        if force or self._should_refresh():
            self._download_oui()

        if not CACHE_FILE.exists():
            logger.warning("No OUI database available. Vendor lookup will be limited.")
            return

        try:
            content = CACHE_FILE.read_text(encoding="utf-8", errors="ignore")
            self.oui_map = {}

            # Supports both IEEE format and simpler "arpalert" style files
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # IEEE style: 00-00-00   (base 16)   XEROX CORPORATION
                if "(base 16)" in line:
                    match = re.match(r"^\s*([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2})", line)
                    if match:
                        oui = match.group(1).replace(":", "").replace("-", "").upper()
                        vendor = line.split("(base 16)", 1)[-1].strip()
                        if vendor:
                            self.oui_map[oui] = vendor
                        continue

                # Simple format: 000000 Xerox Corporation (or tab/comma separated)
                parts = re.split(r'[\t, ]+', line, maxsplit=1)
                if len(parts) == 2:
                    oui = parts[0].replace(":", "").replace("-", "").upper()[:6]
                    vendor = parts[1].strip()
                    if len(oui) == 6 and vendor:
                        self.oui_map[oui] = vendor

            self.last_loaded = time.time()
            logger.info("Loaded %d MAC vendor entries from IEEE OUI database", len(self.oui_map))
        except Exception as e:
            logger.error("Failed to parse OUI database: %s", e)

    def lookup(self, mac: str) -> Optional[str]:
        """Return vendor name or None."""
        if not mac or not self.oui_map:
            return None

        # Normalize MAC: take first 6 hex characters
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) < 6:
            return None

        oui = clean[:6]
        return self.oui_map.get(oui)

    def get_device_category_and_icon(self, vendor: Optional[str]) -> Tuple[str, str]:
        """
        Returns (category, icon) based on vendor name.
        This is used for quick visual identification and to help the AI
        understand what "normal" behavior looks like for this class of device.
        """
        if not vendor:
            return "Unknown", "❓"

        v = vendor.lower()

        # === Phones / Mobile ===
        if any(x in v for x in ["apple", "iphone", "ipad", "macbook", "imac"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["samsung", "galaxy"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["google", "pixel"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["huawei", "honor"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["xiaomi", "redmi", "poco"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["oneplus", "oppo", "vivo", "realme"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["motorola", "moto", "lenovo"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["sony", "ericsson"]):
            return "Phone / Tablet", "📱"

        # === Computers / Laptops ===
        if any(x in v for x in ["dell", "hp inc", "hewlett", "lenovo", "thinkpad", "asus", "msi", "acer", "gigabyte"]):
            return "Computer / Laptop", "💻"
        if any(x in v for x in ["intel", "amd"]):  # often appears on motherboards/NICs
            return "Computer / Component", "💻"

        # === Networking / Routers ===
        if any(x in v for x in ["tp-link", "tplink", "netgear", "asus", "ubiquiti", "ubnt", "cisco", "meraki",
                                 "d-link", "dlink", "linksys", "zyxel", "mikrotik", "edgerouter", "unifi"]):
            return "Router / Network", "📡"
        if any(x in v for x in ["broadcom", "qualcomm", "atheros", "realtek"]):
            return "Network Component", "📡"

        # === NAS / Storage ===
        if any(x in v for x in ["synology", "qnap", "western digital", "wd", "seagate", "buffalo", "drobo", "truenas"]):
            return "NAS / Storage", "🖥️"

        # === Security Cameras / Surveillance ===
        if any(x in v for x in ["hikvision", "dahua", "axis", "reolink", "foscam", "amcrest", "lorex", "swann",
                                 "ubiquiti" and "camera", "onvif"]):
            return "Security Camera", "📹"
        if any(x in v for x in ["ring", "nest", "arlo"]):
            return "Security Camera", "📹"

        # === Smart Home / IoT ===
        if any(x in v for x in ["philips", "hue", "sengled", "tp-link" and "bulb", "yeelight"]):
            return "Smart Home / Lighting", "💡"
        if any(x in v for x in ["ecobee", "nest" and "thermostat", "honeywell", "tado"]):
            return "Smart Home / Climate", "🌡️"
        if any(x in v for x in ["august", "schlage", "yale"]):
            return "Smart Home / Lock", "🔐"
        if any(x in v for x in ["espressif", "esp", "particle", "arduino", "raspberry", "wemos"]):
            return "IoT / Development Board", "🔌"
        if any(x in v for x in ["sonoff", "tasmota", "shelly"]):
            return "Smart Home / Relay", "🔌"

        # === TVs & Media ===
        if any(x in v for x in ["roku", "amazon" and "fire", "chromecast", "google tv"]):
            return "TV / Streaming", "📺"
        if any(x in v for x in ["lg", "samsung" and "tv", "sony" and "bravia", "tcl", "hisense", "panasonic"]):
            return "TV / Media", "📺"
        if any(x in v for x in ["sonos", "bose", "denon", "marantz", "yamaha"]):
            return "Speaker / Audio", "🔊"

        # === Printers ===
        if any(x in v for x in ["brother", "epson", "canon", "hp inc", "xerox", "ricoh", "kyocera"]):
            return "Printer / Scanner", "🖨️"

        # === Generic IoT / Unknown Smart Devices ===
        if any(x in v for x in ["belkin", "wemo", "insteon", "lutron"]):
            return "Smart Home / IoT", "🏠"

        # Fallback
        return "Other / IoT Device", "🔌"


# Singleton
_mac_vendor: MacVendorLookup | None = None


def get_mac_vendor_lookup() -> MacVendorLookup:
    global _mac_vendor
    if _mac_vendor is None:
        _mac_vendor = MacVendorLookup()
        _mac_vendor.load()
    return _mac_vendor


def refresh_mac_vendors_if_needed():
    """Call this on startup (similar to blacklist)."""
    lookup = get_mac_vendor_lookup()
    if lookup._should_refresh():
        lookup.load(force=True)