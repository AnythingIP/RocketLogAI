"""Natural-language parsing for assistant operator commands (ping, etc.)."""

from __future__ import annotations

import platform
import re
import subprocess
from typing import Any

# Words that must never be treated as ping hostnames
_STOP_WORDS = frozenset({
    "my", "the", "a", "an", "our", "your", "this", "that", "some", "any",
    "can", "you", "please", "could", "would", "will", "do", "to", "or", "and",
})

_DNS_TARGETS = ("1.1.1.1", "8.8.8.8")

_CONVERSATIONAL_HINTS = re.compile(
    r"\b(how\s+(?:do|can|to)|should\s+i|what\s+is|explain|help\s+me\s+understand|why\s+would)\b",
    re.I,
)


def _ping_cmd(host: str) -> str:
    if platform.system() == "Windows":
        return f"ping -n 4 {host}"
    return f"ping -c 4 {host}"


def get_default_gateway() -> str | None:
    """Best-effort default gateway for the RocketLogAI host."""
    try:
        if platform.system() == "Windows":
            proc = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=15,
                encoding="utf-8",
                errors="replace",
            )
            for line in (proc.stdout or "").splitlines():
                m = re.match(r"\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+", line)
                if m:
                    gw = m.group(1)
                    if not gw.startswith("0."):
                        return gw
        else:
            proc = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            m = re.search(r"default via (\d{1,3}(?:\.\d{1,3}){3})", proc.stdout or "")
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


def _is_valid_literal_host(token: str) -> bool:
    token = token.strip().lower().rstrip(".")
    if not token or token in _STOP_WORDS:
        return False
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", token):
        return True
    if re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", token) and "." in token:
        return True
    if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", token) and token not in _STOP_WORDS:
        return len(token) > 2
    return False


def _normalize_question(question: str) -> str:
    q = question.strip()
    q = re.sub(
        r"^(?:can you|could you|would you|please|will you)\s+",
        "",
        q,
        flags=re.I,
    )
    return q.strip()


def classify_assistant_input(question: str) -> str:
    """
    Returns:
      - operator_explicit: ping 8.8.8.8
      - operator_natural: ping my gateway
      - operator_maybe: contains ping but unclear
      - conversational: general question
    """
    ql = question.lower().strip()
    if _CONVERSATIONAL_HINTS.search(ql):
        return "conversational"
    if "ping" not in ql and not _operator_keyword(ql):
        return "conversational"
    if re.search(r"\bping\s+(?:the\s+)?\d{1,3}(?:\.\d{1,3}){3}", ql):
        return "operator_explicit"
    if re.search(r"\b(?:gateway|router|dns|nameserver)\b", ql):
        return "operator_natural"
    if re.search(r"\bping\s+(?:my|the|our)\s+\w+", ql):
        return "operator_natural"
    if re.search(r"\bping\b", ql):
        m = re.search(r"\bping\s+(\S+)", ql)
        if m and _is_valid_literal_host(m.group(1)):
            return "operator_explicit"
        return "operator_maybe"
    return "conversational"


def _operator_keyword(ql: str) -> bool:
    return any(k in ql for k in ("nmap", "traceroute", "ssh ", "traceroute"))


def _resolve_nl_ping_targets(question: str) -> list[dict[str, str]]:
    """Map natural phrases to concrete ping targets."""
    ql = _normalize_question(question).lower()
    targets: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(name: str, ip: str, label: str) -> None:
        if ip and ip not in seen:
            seen.add(ip)
            targets.append({"name": name, "ip": ip, "label": label})

    wants_gateway = bool(re.search(r"\b(?:gateway|default\s+gateway|router)\b", ql))
    wants_dns = bool(re.search(r"\b(?:dns|name\s*server|nameserver)\b", ql))

    if wants_gateway:
        gw = get_default_gateway()
        if gw:
            add("default-gateway", gw, "your default gateway")
        else:
            add("default-gateway", "192.168.1.1", "default gateway (fallback — could not auto-detect)")

    if wants_dns:
        for ip in _DNS_TARGETS:
            add(f"dns-{ip}", ip, f"public DNS ({ip})")

    # "ping the core router" style — try literal hostname after ping if not stopword
    if not targets:
        m = re.search(
            r"\bping\s+(?:my|the|our)?\s*([a-z0-9][\w.-]*)",
            ql,
            re.I,
        )
        if m:
            token = m.group(1).lower()
            if token in ("gateway", "router"):
                gw = get_default_gateway() or "192.168.1.1"
                add("gateway", gw, "gateway")
            elif token in ("dns", "nameserver"):
                add("dns", _DNS_TARGETS[0], "DNS server")
            elif _is_valid_literal_host(token):
                add(token, token, token)

    # Explicit IP anywhere in the sentence
    for ip in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", ql):
        add(ip, ip, ip)

    return targets


def build_ping_plan(
    targets: list[dict[str, str]],
    *,
    conversational: bool = False,
) -> dict[str, Any]:
    steps = []
    plan_targets = []
    for idx, t in enumerate(targets, start=1):
        host = t["ip"]
        label = t.get("label") or host
        cmd = _ping_cmd(host)
        steps.append({
            "step": idx,
            "description": f"Ping {label} ({host})",
            "command": cmd,
            "command_or_action": cmd,
            "os": "host",
            "risk": "low",
        })
        plan_targets.append({"ip": host, "name": label, "os_guess": "unknown"})

    if len(targets) == 1:
        t = targets[0]
        explanation = (
            f"I'll ping {t.get('label', t['ip'])} ({t['ip']}) from this RocketLogAI server "
            f"({platform.system()}) to check reachability."
        )
    else:
        labels = ", ".join(t.get("label", t["ip"]) for t in targets)
        explanation = (
            f"I'll run reachability checks from this server against: {labels}."
        )

    if not conversational:
        explanation += " Review the steps, then confirm (or enable session trust to skip confirm on later pings)."

    return {
        "is_operator_command": True,
        "is_actionable": True,
        "intent": "ping",
        "explanation": explanation,
        "targets": plan_targets,
        "proposed_steps": steps,
        "requires_confirmation": True,
        "backup_recommended": False,
        "rollback_notes": "Read-only ICMP tests; nothing to roll back.",
        "safety_notes": "Runs ping on the RocketLogAI host only.",
        "nl_parsed": True,
    }


def build_operator_plan_from_question(
    question: str,
    storage: Any = None,
) -> dict[str, Any] | None:
    """Build an operator plan from explicit or natural-language ping requests."""
    if _CONVERSATIONAL_HINTS.search(question):
        return None

    ql = _normalize_question(question).lower()
    if "ping" not in ql:
        return None

    kind = classify_assistant_input(question)

    # Explicit: ping 192.168.20.1
    m = re.search(r"\bping\s+(?:the\s+)?(\d{1,3}(?:\.\d{1,3}){3})\b", ql)
    if m:
        ip = m.group(1)
        return build_ping_plan([{"name": ip, "ip": ip, "label": ip}])

    # Natural language targets
    if kind in ("operator_natural", "operator_maybe"):
        targets = _resolve_nl_ping_targets(question)
        if targets:
            return build_ping_plan(targets, conversational=kind == "operator_natural")

    # Literal hostname only if valid (not "my")
    m = re.search(r"\bping\s+(?:the\s+)?([a-z0-9][\w.-]*)\b", ql, re.I)
    if m and _is_valid_literal_host(m.group(1)):
        host = m.group(1).rstrip(".")
        return build_ping_plan([{"name": host, "ip": host, "label": host}])

    return None