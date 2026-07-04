"""
WAF engine for decrypted traffic inspection.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WAFRule:
    id: str
    name: str
    pattern: str
    severity: str = "high"
    action: str = "block"  # block | log | challenge
    enabled: bool = True
    _compiled: re.Pattern | None = field(default=None, repr=False)

    def matches(self, payload: str) -> bool:
        if not self.enabled:
            return False
        if self._compiled is None:
            self._compiled = re.compile(self.pattern, re.IGNORECASE)
        return bool(self._compiled.search(payload))


DEFAULT_WAF_RULES = [
    WAFRule("sqli-001", "SQL Injection", r"(union\s+select|or\s+1\s*=\s*1|drop\s+table)", "critical"),
    WAFRule("xss-001", "XSS Attack", r"(<script|javascript:|onerror\s*=)", "high"),
    WAFRule("path-001", "Path Traversal", r"(\.\./|\.\.\\|%2e%2e)", "high"),
    WAFRule("cmd-001", "Command Injection", r"(;\s*(cat|wget|curl|bash|sh)\s)", "critical"),
]


class WAFEngine:
    """Web Application Firewall for inline/SPAN decrypted traffic."""

    def __init__(self, rules: list[WAFRule] | None = None, block_mode: str = "detect"):
        self.rules = rules or list(DEFAULT_WAF_RULES)
        self.block_mode = block_mode
        self._events: list[dict[str, Any]] = []

    def inspect(self, request: dict[str, Any]) -> dict[str, Any]:
        """Inspect HTTP request dict with url, headers, body fields."""
        combined = " ".join([
            request.get("url", ""),
            str(request.get("headers", {})),
            request.get("body", ""),
        ])
        matches = []
        for rule in self.rules:
            if rule.matches(combined):
                matches.append({"rule_id": rule.id, "name": rule.name, "severity": rule.severity, "action": rule.action})

        blocked = any(m["action"] == "block" for m in matches) and self.block_mode == "block"
        event = {
            "ts": time.time(),
            "source_ip": request.get("source_ip", ""),
            "url": request.get("url", ""),
            "matches": matches,
            "blocked": blocked,
        }
        self._events.append(event)
        if len(self._events) > 1000:
            self._events = self._events[-500:]

        return {
            "allowed": not blocked,
            "matches": matches,
            "action": "block" if blocked else ("log" if matches else "allow"),
        }

    def add_rule(self, rule: WAFRule) -> None:
        self.rules.append(rule)

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._events[-limit:]

    def status(self) -> dict[str, Any]:
        return {
            "rules": len(self.rules),
            "block_mode": self.block_mode,
            "recent_events": len(self._events),
        }