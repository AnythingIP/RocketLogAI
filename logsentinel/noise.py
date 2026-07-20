"""
Noise / false-positive helpers for home-lab syslog (UniFi/Omada AP flows, HA IoT, etc.).

Used by the analyzer before LLM calls and after LLM output, and by sweep tools.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

# UniFi / Omada / similar AP client traffic accounting (NOT IDS alerts)
AP_FLOW_RE = re.compile(
    r"AP\s*MAC\s*=\s*[0-9a-fA-F:.\-]{11,}.*?"
    r"(?:IP\s*SRC|MAC\s*SRC)\s*=",
    re.I | re.S,
)
# Flow tuple without AP MAC prefix (still traffic accounting)
FLOW_TUPLE_RE = re.compile(
    r"IP\s*SRC\s*=\s*\d{1,3}(?:\.\d{1,3}){3}\s+"
    r"IP\s*DST\s*=\s*\d{1,3}(?:\.\d{1,3}){3}\s+"
    r"IP\s*proto\s*=\s*\d+",
    re.I,
)

# Threat description / evidence phrases that are almost always false on home LAN flow logs
FP_DESC_RE = re.compile(
    r"(?i)("
    r"syn\s*flood|syn\s*attack|tcp\s*syn\s*flood|"
    r"icmp\s*(echo\s*)?(attack|flood)|"
    r"ddos|denial\s*of\s*service|"
    r"port\s*scan(ning)?|"
    r"invalid\s*protocol|"
    r"ip\s*proto\s*=\s*6\b.*invalid|"
    r"potential\s*tcp\s*(connection\s*)?attempt"  # alone is not a threat
    r")"
)

# Home Assistant / Mosquitto / Samba home-lab noise (not attacks)
HA_NOISE_RE = re.compile(
    r"(?i)("
    r"addon_core_mosquitto|mosquitto.*(new connection|client .* disconnect)|"
    r"New connection from 172\.30\.|"  # HA docker internal
    r"addon_core_samba|unpack_canon_ace|"
    r"homeassistant\.components\.rest_command|"
    r"max\.\s*payload\s*size"  # size limit, not exploit payload
    r")"
)

PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
]

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in PRIVATE_NETS)


def extract_ips(text: str) -> list[str]:
    return [m.group(1) for m in _IP_RE.finditer(text or "")]


def is_ap_flow_log(message: str, raw: str | None = None) -> bool:
    """True if this syslog line is Wi‑Fi AP client flow accounting."""
    hay = f"{message or ''}\n{raw or ''}"
    if AP_FLOW_RE.search(hay):
        return True
    # Batched multi-line AP dumps often start with facility + AP MAC lines
    if "AP MAC=" in hay and "IP SRC=" in hay and "IP proto=" in hay:
        return True
    return False


def is_flow_tuple_only(message: str, raw: str | None = None) -> bool:
    hay = f"{message or ''}\n{raw or ''}"
    if is_ap_flow_log(message, raw):
        return True
    # Pure flow lines without security keywords
    if FLOW_TUPLE_RE.search(hay) and not re.search(
        r"(?i)(deny|block|drop|reject|failed password|invalid user|malware|exploit)",
        hay,
    ):
        return True
    return False


def is_ha_lab_noise(message: str, raw: str | None = None, hostname: str | None = None) -> bool:
    hay = " ".join(x for x in [hostname or "", message or "", raw or ""] if x)
    return bool(HA_NOISE_RE.search(hay))


def should_skip_llm(record: dict[str, Any]) -> bool:
    """Logs that should not be sent to the LLM as threat candidates."""
    msg = record.get("message") or ""
    raw = record.get("raw") or ""
    host = record.get("hostname")
    if is_ap_flow_log(msg, raw) or is_flow_tuple_only(msg, raw):
        return True
    if is_ha_lab_noise(msg, raw, host):
        return True
    return False


def evidence_blob(threat: dict[str, Any]) -> str:
    ev = threat.get("evidence") or []
    if isinstance(ev, list):
        return "\n".join(str(x) for x in ev)
    return str(ev)


def is_likely_false_positive_threat(threat: dict[str, Any]) -> tuple[bool, str]:
    """
    Post-LLM / bulk-sweep classifier.
    Returns (is_fp, reason).
    """
    desc = (threat.get("description") or "").strip()
    ev = evidence_blob(threat)
    hay = f"{desc}\n{ev}"

    # AP client traffic accounting (UniFi/Omada) is never an IDS signature by itself
    if is_ap_flow_log(ev) or is_ap_flow_log(desc) or (
        "AP MAC=" in hay and "IP SRC=" in hay and "IP proto=" in hay
    ):
        return True, "unifi_ap_flow_accounting"

    if FLOW_TUPLE_RE.search(hay) and (FP_DESC_RE.search(desc) or FP_DESC_RE.search(ev)):
        ips = extract_ips(hay)
        if ips and all(_is_private_ip(ip) for ip in ips):
            return True, "lan_flow_labeled_as_attack"

    # ICMP to gateway / LAN only
    if re.search(r"(?i)icmp", desc) and re.search(r"IP proto\s*=\s*1\b", hay):
        ips = extract_ips(hay)
        if ips and all(_is_private_ip(ip) for ip in ips):
            return True, "lan_icmp_noise"

    # LLM invents "invalid protocol" for TCP (proto 6)
    if re.search(r"(?i)invalid\s+protocol|proto\s*=\s*6.*invalid", hay):
        return True, "proto6_is_tcp"

    # HA mosquitto / samba / rest_command noise
    if is_ha_lab_noise(desc, ev, threat.get("hostname")):
        return True, "home_assistant_lab_noise"

    # "Possible exploit or shellcode" with only payload size / rest_command evidence
    if re.search(r"(?i)exploit|shellcode", desc) and re.search(
        r"(?i)max\.\s*payload|rest_command|payload size", hay
    ):
        return True, "payload_size_not_exploit"

    # All-private endpoints + generic "TCP connection attempt" / high rate 443 = FP
    if re.search(r"(?i)(tcp connection attempt|outbound connections to port 443|high-frequency outbound)", desc):
        ips = extract_ips(hay)
        if ips and all(_is_private_ip(ip) or ip.startswith(("13.", "17.", "34.", "52.", "54.", "99.", "104.")) for ip in ips):
            # outbound HTTPS to CDN/AWS is normal
            if re.search(r"(?i)port 443|DPT=443|proto=6.*443", hay) or "443" in desc:
                return True, "normal_https_or_lan_tcp"

    # Common LLM hallucination classes on pure LAN evidence (no external IP)
    ips = extract_ips(hay)
    if ips and all(_is_private_ip(ip) for ip in ips):
        if re.search(
            r"(?i)(port\s*scan|ddos|syn\s*flood|flood attack|denial of service|"
            r"unusual outbound|suspicious traffic|potential attack)",
            desc,
        ):
            # No firewall deny/drop language → treat as noise
            if not re.search(r"(?i)(deny|denied|drop|block|reject|failed password|invalid user)", hay):
                return True, "lan_only_llm_attack_label"

    return False, ""


def filter_threats(threats: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split threats into (kept, dropped_fps)."""
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for t in threats:
        fp, reason = is_likely_false_positive_threat(t)
        if fp:
            t = dict(t)
            t["_fp_reason"] = reason
            dropped.append(t)
        else:
            kept.append(t)
    return kept, dropped
