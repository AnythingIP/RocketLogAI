"""
Syslog message parser supporting RFC 3164 and RFC 5424.

Returns a normalized dict for every message.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# Common syslog priority to (facility, severity)
FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "audit", 14: "alert",
    15: "clock", 16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

SEVERITY_NAMES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

# RFC3164: <PRI>Mon dd HH:MM:SS host tag[pid]: message
# Very loose because many devices are sloppy.
RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>\s*"
    r"(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>[\w\.\-]+)\s+"
    r"(?P<tag>[\w\.\-\[\]/]+):\s*"
    r"(?P<message>.*)$"
)

# RFC5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [STRUCTURED-DATA] MSG
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:\[.*?\])|-)\s*"
    r"(?P<message>.*)$"
)

# Fallback for weird devices that just send <PRI>message
BASIC_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>\s*(?P<message>.*)$")


def parse_pri(pri: int) -> dict[str, Any]:
    """Split PRI into facility and severity."""
    facility = (pri >> 3) & 0x1F
    severity = pri & 0x07
    return {
        "facility": FACILITY_NAMES.get(facility, f"local{facility-16}" if facility >= 16 else str(facility)),
        "facility_code": facility,
        "severity": SEVERITY_NAMES.get(severity, str(severity)),
        "severity_code": severity,
        "priority": pri,
    }


def _parse_rfc3164_timestamp(ts: str) -> datetime | None:
    """Parse 'Mar  5 14:23:01' style. Year is missing, assume current year."""
    try:
        # Add current year
        now = datetime.now()
        ts_with_year = f"{ts} {now.year}"
        dt = datetime.strptime(ts_with_year, "%b %d %H:%M:%S %Y")
        # If the date is in the future (e.g. Dec log parsed in Jan), roll back year
        if dt > now + timedelta(days=1):
            dt = dt.replace(year=now.year - 1)
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def parse_syslog_message(raw: str) -> dict[str, Any]:
    """
    Parse a raw syslog line into a normalized record.

    Returns dict with keys:
      raw, timestamp, hostname, appname, procid, msgid,
      facility, severity, message, structured_data, format
    """
    from datetime import timedelta  # local import to avoid top-level pollution

    raw = raw.strip()
    if not raw:
        return {"raw": raw, "message": "", "format": "empty"}

    # Try RFC5424 first (more structured)
    m = RFC5424_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        pri_info = parse_pri(pri)
        ts_str = m.group("timestamp")
        try:
            # ISO8601 or RFC3339
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            ts = datetime.fromisoformat(ts_str)
        except Exception:
            ts = datetime.now(timezone.utc)

        return {
            "raw": raw,
            "timestamp": ts.isoformat(),
            "hostname": m.group("hostname") if m.group("hostname") != "-" else None,
            "appname": m.group("appname") if m.group("appname") != "-" else None,
            "procid": m.group("procid") if m.group("procid") != "-" else None,
            "msgid": m.group("msgid") if m.group("msgid") != "-" else None,
            "structured_data": m.group("structured_data") if m.group("structured_data") != "-" else None,
            "message": m.group("message").strip(),
            **pri_info,
            "format": "rfc5424",
        }

    # RFC 3164
    m = RFC3164_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        pri_info = parse_pri(pri)
        ts = _parse_rfc3164_timestamp(m.group("timestamp")) or datetime.now(timezone.utc)

        tag = m.group("tag")
        appname = tag
        procid = None
        if "[" in tag:
            appname, rest = tag.split("[", 1)
            procid = rest.rstrip("]")

        return {
            "raw": raw,
            "timestamp": ts.isoformat(),
            "hostname": m.group("hostname"),
            "appname": appname,
            "procid": procid,
            "msgid": None,
            "structured_data": None,
            "message": m.group("message").strip(),
            **pri_info,
            "format": "rfc3164",
        }

    # Very basic <PRI>message fallback (many devices do this)
    m = BASIC_PRI_RE.match(raw)
    if m:
        pri = int(m.group("pri"))
        pri_info = parse_pri(pri)
        return {
            "raw": raw,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "hostname": None,
            "appname": None,
            "procid": None,
            "msgid": None,
            "structured_data": None,
            "message": m.group("message").strip(),
            **pri_info,
            "format": "basic",
        }

    # Last resort: treat whole thing as message, assume info
    return {
        "raw": raw,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": None,
        "appname": None,
        "procid": None,
        "msgid": None,
        "structured_data": None,
        "message": raw,
        "facility": "user",
        "facility_code": 1,
        "severity": "info",
        "severity_code": 6,
        "priority": 14,
        "format": "unknown",
    }


def severity_to_int(sev: str) -> int:
    """Map severity name to numeric value (higher = worse)."""
    mapping = {
        "emergency": 7, "alert": 6, "critical": 5, "error": 4,
        "warning": 3, "notice": 2, "info": 1, "debug": 0,
    }
    return mapping.get(sev.lower(), 1)
