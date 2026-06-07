"""
MAC Address Vendor / Manufacturer Lookup for RocketLogAI.

Provides offline-capable device type identification (Phone, IoT, TV, NAS, Router, etc.)
using high-quality sources recommended for accuracy:
- Wireshark manuf (primary, recommended, compact + full names + variable length prefixes)
- IEEE OUI / IAB / MAM public listings (full org details)
- Optional: maclookup.app CSV (user can place in data/mac_vendors/)

This enables:
- Accurate vendor identification for any MAC (OUI + longer allocations)
- Rich device details (vendor name, short name, country/address hints) for admins
- Better AI decisions: "is this traffic typical for an Apple iPhone or a Hikvision camera?"
- Foundation for automatic port-based trust: AI derives expected ports per vendor/category
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import requests

logger = logging.getLogger(__name__)

MAC_VENDOR_DIR = Path("data/mac_vendors")
MAC_VENDOR_DIR.mkdir(parents=True, exist_ok=True)

# === Recommended sources (user-specified) ===
# 1. Wireshark manuf - primary, excellent coverage, updated frequently, supports /28 /36 prefixes
WIRESHARK_MANUF_URL = "https://www.wireshark.org/download/automated/data/manuf"
WIRESHARK_CACHE = MAC_VENDOR_DIR / "manuf"

# 2. IEEE official (OUI + IAB + MAM + CID for full coverage)
IEEE_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"
IEEE_IAB_URL = "https://standards-oui.ieee.org/iab/iab.txt"
IEEE_MAM_URL = "https://standards-oui.ieee.org/oui28/mam.txt"
IEEE_CID_URL = "https://standards-oui.ieee.org/oui36/cid.txt"

IEEE_CACHE = MAC_VENDOR_DIR / "ieee-oui.txt"

# 3. maclookup.app (large CSV, optional - place manually or we can support download later)
MACLOOKUP_CSV = MAC_VENDOR_DIR / "maclookup.csv"

CACHE_AGE_SECONDS = 86400 * 14   # 14 days (these are large-ish; manuf ~3MB)


class MacVendorLookup:
    def __init__(self):
        # Primary map: prefix (variable length hex) -> rich entry
        # e.g. "001BC5000" -> {"vendor": "...", "short": "...", "bits": 36, "source": "wireshark"}
        self.vendor_map: Dict[str, dict] = {}
        # Simple backward compat 6-char OUI -> name str (populated during load)
        self.oui_map: Dict[str, str] = {}
        self.last_loaded = 0
        self.sources_used: List[str] = []

    def _download_file(self, url: str, dest: Path, label: str) -> bool:
        try:
            resp = requests.get(url, timeout=60, headers={"User-Agent": "RocketLogAI/1.1 (vendor lookup)"})
            resp.raise_for_status()
            dest.write_text(resp.text, encoding="utf-8")
            logger.info("Downloaded %s (%d bytes) -> %s", label, len(resp.text), dest)
            return True
        except Exception as e:
            logger.warning("Failed to download %s from %s: %s", label, url, e)
            return False

    def _should_refresh(self, path: Path) -> bool:
        if not path.exists():
            return True
        age = time.time() - path.stat().st_mtime
        return age > CACHE_AGE_SECONDS

    def load(self, force: bool = False):
        """Load best available vendor DBs. Prefers Wireshark manuf (recommended)."""
        loaded_any = False
        self.vendor_map = {}
        self.oui_map = {}
        self.sources_used = []

        # 1. Wireshark manuf (primary)
        if force or self._should_refresh(WIRESHARK_CACHE):
            self._download_file(WIRESHARK_MANUF_URL, WIRESHARK_CACHE, "Wireshark manuf")
        if WIRESHARK_CACHE.exists():
            try:
                n = self._parse_wireshark_manuf(WIRESHARK_CACHE)
                if n > 0:
                    self.sources_used.append("wireshark-manuf")
                    loaded_any = True
                    logger.info("Loaded %d entries from Wireshark manuf", n)
            except Exception as e:
                logger.error("Failed parsing Wireshark manuf: %s", e)

        # 2. IEEE full (OUI + IAB + MAM) for extra coverage + org details
        if force or self._should_refresh(IEEE_CACHE):
            # Download main OUI; others optional (larger total)
            self._download_file(IEEE_OUI_URL, IEEE_CACHE, "IEEE OUI")
            # Try extras non-blocking
            for url, name in [(IEEE_IAB_URL, "IAB"), (IEEE_MAM_URL, "MAM")]:
                try:
                    p = MAC_VENDOR_DIR / f"ieee-{name.lower()}.txt"
                    self._download_file(url, p, f"IEEE {name}")
                except Exception:
                    pass
        if IEEE_CACHE.exists():
            try:
                n = self._parse_ieee_file(IEEE_CACHE)
                if n > 0:
                    self.sources_used.append("ieee-oui")
                    loaded_any = True
            except Exception as e:
                logger.error("Failed parsing IEEE: %s", e)

        # 3. Optional maclookup.csv (user-provided, large)
        if MACLOOKUP_CSV.exists():
            try:
                n = self._parse_maclookup_csv(MACLOOKUP_CSV)
                if n > 0:
                    self.sources_used.append("maclookup")
            except Exception as e:
                logger.warning("maclookup parse skipped: %s", e)

        if not loaded_any:
            logger.warning("No MAC vendor database available. Vendor lookup will be limited.")
            return

        self.last_loaded = time.time()
        logger.info("MAC vendor lookup ready. Sources: %s | Total prefixes: %d", ", ".join(self.sources_used) or "none", len(self.vendor_map))

    def _parse_wireshark_manuf(self, path: Path) -> int:
        """Parse Wireshark manuf. Supports 24/28/36 bit prefixes and /nn notation."""
        count = 0
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Formats seen:
            # 00:00:01         Xerox       Xerox Corporation
            # 00:1B:C5:00:00/36Converging  Converging Systems Inc.   (sometimes no space before /)
            m = re.match(r'^([0-9A-Fa-f:.-]+?)(?:/(\d+))?\s+([^\t]+?)\s{2,}(.*)$', line)
            if not m:
                # fallback looser
                m = re.match(r'^([0-9A-Fa-f:.-]+?)(?:/(\d+))?\s+(\S+)\s+(.*)$', line)
            if not m:
                continue
            prefix_raw, bits_str, short_name, full_name = m.groups()
            prefix = re.sub(r'[^0-9A-Fa-f]', '', prefix_raw).upper()
            if not prefix:
                continue
            bits = int(bits_str) if bits_str else (len(prefix) * 4)
            vendor = (full_name or short_name or "").strip()
            if not vendor:
                continue
            # Store longest match wins later
            entry = {
                "vendor": vendor,
                "short": short_name.strip() if short_name else vendor[:20],
                "bits": bits,
                "source": "wireshark"
            }
            # Only keep if longer or not present (prefer detailed)
            existing = self.vendor_map.get(prefix)
            if not existing or bits > existing.get("bits", 0):
                self.vendor_map[prefix] = entry
            # Also populate simple 6-char for compat if applicable
            if len(prefix) >= 6:
                self.oui_map[prefix[:6]] = vendor
            count += 1
        return count

    def _parse_ieee_file(self, path: Path) -> int:
        """Parse classic IEEE (base 16) + hex blocks. Captures org name + tries for country."""
        count = 0
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line or line.startswith("#"):
                i += 1
                continue
            vendor = None
            prefix = None
            extra = ""
            if "(base 16)" in line:
                m = re.match(r"^\s*([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2})", line)
                if m:
                    prefix = m.group(1).replace(":", "").replace("-", "").upper()
                    vendor = line.split("(base 16)", 1)[-1].strip()
            elif "(hex)" in line.lower():
                m = re.match(r"^\s*([0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2}[-:]?[0-9A-Fa-f]{2})", line)
                if m:
                    prefix = m.group(1).replace(":", "").replace("-", "").upper()
                    # next line often has (base 16)
                    if i + 1 < len(lines) and "(base 16)" in lines[i+1]:
                        vendor = lines[i+1].split("(base 16)", 1)[-1].strip()
                        i += 1
            else:
                # simple tab / space 000000\tVendor
                parts = re.split(r'[\t, ]+', line, maxsplit=1)
                if len(parts) == 2 and len(re.sub(r'[^0-9A-Fa-f]', '', parts[0])) == 6:
                    prefix = re.sub(r'[^0-9A-Fa-f]', '', parts[0]).upper()[:6]
                    vendor = parts[1].strip()

            if prefix and vendor:
                # Try to grab address/country from following indented lines (IEEE style)
                j = i + 1
                addr_lines = []
                while j < len(lines) and (lines[j].startswith("\t") or lines[j].startswith(" ") or not lines[j].strip()):
                    s = lines[j].strip()
                    if s and not s.startswith("#") and not "(base" in s and not "(hex)" in s.lower():
                        addr_lines.append(s)
                    j += 1
                    if len(addr_lines) > 4:
                        break
                if addr_lines:
                    extra = " | " + " ".join(addr_lines[-2:])  # last 1-2 lines often city, country

                entry = {
                    "vendor": vendor + extra,
                    "short": vendor.split()[0] if vendor else vendor,
                    "bits": 24 if len(prefix) == 6 else 28,
                    "source": "ieee"
                }
                if prefix not in self.vendor_map or entry["bits"] >= self.vendor_map.get(prefix, {}).get("bits", 0):
                    self.vendor_map[prefix] = entry
                self.oui_map[prefix[:6]] = vendor
                count += 1
            i += 1
        return count

    def _parse_maclookup_csv(self, path: Path) -> int:
        """Best-effort parse for maclookup.app style CSV (header usually mac_prefix,vendor,country,...)"""
        count = 0
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            first = True
            for line in content.splitlines():
                if first:
                    first = False
                    if "vendor" not in line.lower() and "company" not in line.lower():
                        # no header? treat as data
                        pass
                    else:
                        continue
                parts = [p.strip().strip('"') for p in line.split(",")]
                if len(parts) < 2:
                    continue
                prefix = re.sub(r'[^0-9A-Fa-f]', '', parts[0]).upper()[:9]  # up to 36bit
                vendor = parts[1] or parts[2] if len(parts) > 2 else ""
                if len(prefix) >= 6 and vendor:
                    self.vendor_map[prefix] = {"vendor": vendor, "short": vendor[:18], "bits": len(prefix)*4, "source": "maclookup"}
                    self.oui_map[prefix[:6]] = vendor
                    count += 1
        except Exception:
            pass
        return count

    def _longest_prefix_match(self, clean_mac: str) -> Optional[dict]:
        """Find best (longest) prefix match for a normalized MAC hex string."""
        if not clean_mac or len(clean_mac) < 6 or not self.vendor_map:
            return None
        # Try longest possible first (36bit=9 hex, 28bit=7, 24bit=6)
        for length in (9, 8, 7, 6):
            if length > len(clean_mac):
                continue
            p = clean_mac[:length]
            if p in self.vendor_map:
                return self.vendor_map[p]
        # Fallback: any 6-char
        return self.vendor_map.get(clean_mac[:6])

    def lookup(self, mac: str) -> Optional[str]:
        """Return best vendor name (full) or None. Backward compatible."""
        if not mac:
            return None
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) < 6:
            return None
        entry = self._longest_prefix_match(clean)
        if entry:
            return entry.get("vendor")
        # last resort simple map
        return self.oui_map.get(clean[:6])

    def lookup_detailed(self, mac: str) -> Optional[dict]:
        """Return rich vendor info for UI + AI: vendor, short, category, icon, bits, source, prefix."""
        if not mac:
            return None
        clean = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
        if len(clean) < 6:
            return None
        entry = self._longest_prefix_match(clean)
        if not entry:
            # fallback
            name = self.oui_map.get(clean[:6])
            if not name:
                return None
            entry = {"vendor": name, "short": name[:20], "bits": 24, "source": "legacy"}

        cat, icon = self.get_device_category_and_icon(entry.get("vendor"))
        return {
            "vendor": entry.get("vendor"),
            "short_vendor": entry.get("short"),
            "prefix_matched": clean[: (entry.get("bits", 24)//4) ] if entry.get("bits") else clean[:6],
            "bits": entry.get("bits", 24),
            "source": entry.get("source", "unknown"),
            "device_category": cat,
            "vendor_icon": icon,
            "details": f"Matched {entry.get('bits',24)}bit prefix from {entry.get('source')}"
        }

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
        if any(x in v for x in ["apple", "iphone", "ipad", "macbook", "imac", "apple, inc"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["samsung", "galaxy", "samsung electronics"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["google", "pixel", "google, inc"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["huawei", "honor"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["xiaomi", "redmi", "poco"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["oneplus", "oppo", "vivo", "realme"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["motorola", "moto", "lenovo"]):
            return "Phone / Tablet", "📱"
        if any(x in v for x in ["sony", "ericsson", "sony mobile"]):
            return "Phone / Tablet", "📱"

        # === Computers / Laptops ===
        if any(x in v for x in ["dell", "hp inc", "hewlett", "lenovo", "thinkpad", "asus", "msi", "acer", "gigabyte", "framework"]):
            return "Computer / Laptop", "💻"
        if any(x in v for x in ["intel", "amd", "nvidia"]):  # often appears on motherboards/NICs
            return "Computer / Component", "💻"

        # === Networking / Routers ===
        if any(x in v for x in ["tp-link", "tplink", "netgear", "asus", "ubiquiti", "ubnt", "cisco", "meraki",
                                 "d-link", "dlink", "linksys", "zyxel", "mikrotik", "edgerouter", "unifi", "juniper", "aruba"]):
            return "Router / Network", "📡"
        if any(x in v for x in ["broadcom", "qualcomm", "atheros", "realtek", "marvell", "mediatek"]):
            return "Network Component", "📡"

        # === NAS / Storage ===
        if any(x in v for x in ["synology", "qnap", "western digital", "wd", "seagate", "buffalo", "drobo", "truenas", "netapp"]):
            return "NAS / Storage", "🖥️"

        # === Security Cameras / Surveillance ===
        if any(x in v for x in ["hikvision", "dahua", "axis", "reolink", "foscam", "amcrest", "lorex", "swann", "onvif"]):
            return "Security Camera", "📹"
        if any(x in v for x in ["ring", "nest", "arlo", "eufy"]):
            return "Security Camera", "📹"

        # === Smart Home / IoT ===
        if any(x in v for x in ["philips", "hue", "sengled", "yeelight"]):
            return "Smart Home / Lighting", "💡"
        if any(x in v for x in ["ecobee", "honeywell", "tado", "thermostat"]):
            return "Smart Home / Climate", "🌡️"
        if any(x in v for x in ["august", "schlage", "yale", "kwikset"]):
            return "Smart Home / Lock", "🔐"
        if any(x in v for x in ["espressif", "esp", "particle", "arduino", "raspberry", "wemos", "raspberry pi"]):
            return "IoT / Development Board", "🔌"
        if any(x in v for x in ["sonoff", "tasmota", "shelly", "tuya"]):
            return "Smart Home / Relay", "🔌"

        # === TVs & Media ===
        if any(x in v for x in ["roku", "amazon" and "fire", "chromecast", "google tv", "fire tv"]):
            return "TV / Streaming", "📺"
        if any(x in v for x in ["lg", "samsung" and "tv", "sony" and "bravia", "tcl", "hisense", "panasonic", "vizio"]):
            return "TV / Media", "📺"
        if any(x in v for x in ["sonos", "bose", "denon", "marantz", "yamaha", "harman"]):
            return "Speaker / Audio", "🔊"

        # === Printers ===
        if any(x in v for x in ["brother", "epson", "canon", "hp inc", "xerox", "ricoh", "kyocera", "lexmark"]):
            return "Printer / Scanner", "🖨️"

        # === Generic IoT / Unknown Smart Devices ===
        if any(x in v for x in ["belkin", "wemo", "insteon", "lutron", "leviton"]):
            return "Smart Home / IoT", "🏠"

        # Fallback
        return "Other / IoT Device", "🔌"

    def get_vendor_summary(self) -> dict:
        """For UI / status page."""
        return {
            "sources": self.sources_used,
            "total_prefixes": len(self.vendor_map),
            "last_loaded": self.last_loaded,
            "cache_dir": str(MAC_VENDOR_DIR),
            "has_wireshark": WIRESHARK_CACHE.exists(),
            "has_ieee": IEEE_CACHE.exists(),
        }


# Singleton
_mac_vendor: MacVendorLookup | None = None


def get_mac_vendor_lookup() -> MacVendorLookup:
    global _mac_vendor
    if _mac_vendor is None:
        _mac_vendor = MacVendorLookup()
        _mac_vendor.load()
    return _mac_vendor


def refresh_mac_vendors_if_needed(force: bool = False):
    """Call this on startup (similar to blacklist). Also callable from web UI for manual refresh."""
    lookup = get_mac_vendor_lookup()
    needs = force
    if not needs:
        for p in [WIRESHARK_CACHE, IEEE_CACHE]:
            if lookup._should_refresh(p):
                needs = True
                break
    if needs:
        lookup.load(force=True)
    return lookup.get_vendor_summary()


def get_vendor_databases_status() -> dict:
    """Quick status for dashboard or config page."""
    try:
        lookup = get_mac_vendor_lookup()
        return lookup.get_vendor_summary()
    except Exception as e:
        return {"error": str(e), "sources": [], "total_prefixes": 0}
