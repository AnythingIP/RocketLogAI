"""
Rule-based threat detector.

Fast, deterministic first pass before (or alongside) LLM analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .parser import severity_to_int


@dataclass
class RuleMatch:
    rule_id: str
    severity: str
    score: float  # 0-10
    description: str
    evidence: list[str]


class RuleEngine:
    def __init__(self, custom_patterns: list[str] | None = None):
        self.custom_patterns: list[re.Pattern] = []
        for p in (custom_patterns or []):
            try:
                self.custom_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error:
                pass  # ignore bad user patterns

        # Built-in high-value patterns
        self._builtin: list[tuple[str, re.Pattern, str, float]] = [
            # SSH / authentication brute force
            ("ssh_bruteforce", re.compile(r"Failed password for .* from \S+ port \d+", re.I), "high", 8.5),
            ("ssh_invalid_user", re.compile(r"Invalid user \S+ from \S+", re.I), "high", 7.5),
            ("auth_failure", re.compile(r"authentication failure|failed login|login failed", re.I), "medium", 6.0),

            # Sudo / privilege escalation
            ("sudo_abuse", re.compile(r"sudo:.*(not in sudoers|command not allowed|authentication failure)", re.I), "high", 7.0),
            ("su_attempt", re.compile(r"su\[.*\]:.*(failed|authentication failure)", re.I), "medium", 5.5),

            # Common attack / exploit indicators
            ("exploit_attempt", re.compile(r"(exploit|shellcode|payload|reverse shell|nc -e|/bin/sh -i)", re.I), "critical", 9.0),
            ("base64_command", re.compile(r"echo [A-Za-z0-9+/=]{20,} \| base64 -d", re.I), "high", 8.0),

            # Malware / miner indicators (common in compromised hosts)
            ("crypto_miner", re.compile(r"(xmrig|minerd|cryptonight|stratum\+tcp)", re.I), "critical", 9.5),
            ("suspicious_download", re.compile(r"(wget|curl).*(http|https).*(sh|bash|elf|bin)", re.I), "high", 7.5),

            # Critical system events
            ("kernel_panic", re.compile(r"kernel panic|BUG: unable to handle|segfault.*at", re.I), "critical", 8.5),
            ("oom_killer", re.compile(r"Out of memory|Killed process|oom-killer", re.I), "high", 7.0),

            # Security tooling / audit
            ("selinux_denial", re.compile(r"avc:\s+denied", re.I), "medium", 5.0),
            ("audit_failure", re.compile(r"type=ANOM_(PROMISC|LOGIN|ROOT_TRANS)", re.I), "high", 8.0),

            # Windows / AD style (if forwarded)
            ("windows_failed_logon", re.compile(r"EventID.*4625|failed logon|bad password", re.I), "medium", 6.0),
        ]

    def analyze(self, record: dict[str, Any]) -> list[RuleMatch]:
        """Run all rules against a single normalized log record. Returns matches."""
        matches: list[RuleMatch] = []
        msg = record.get("message", "") or ""
        full = record.get("raw", "") or msg

        # Custom patterns first (user overrides)
        for pat in self.custom_patterns:
            if pat.search(full):
                matches.append(RuleMatch(
                    rule_id="custom",
                    severity="high",
                    score=8.0,
                    description="Custom rule match",
                    evidence=[msg[:300]],
                ))
                break  # one custom match is enough

        for rule_id, pattern, sev, score in self._builtin:
            if pattern.search(full):
                matches.append(RuleMatch(
                    rule_id=rule_id,
                    severity=sev,
                    score=score,
                    description=self._describe(rule_id),
                    evidence=[msg[:400]],
                ))

        # Simple repetition heuristic (caller can enrich with recent history)
        if record.get("severity_code", 0) >= 4:  # warning and above
            if len(msg) < 20 and any(c.isdigit() for c in msg):
                # Very short + numeric often means error codes or port scans
                matches.append(RuleMatch(
                    rule_id="repetitive_error",
                    severity="low",
                    score=3.0,
                    description="Short high-severity message (possible scanning or noise)",
                    evidence=[msg],
                ))

        return matches

    def _describe(self, rule_id: str) -> str:
        return {
            "ssh_bruteforce": "SSH brute-force attempt detected",
            "ssh_invalid_user": "SSH login attempt for non-existent user",
            "auth_failure": "Authentication failure",
            "sudo_abuse": "Unauthorized or failed sudo usage",
            "su_attempt": "Failed su (switch user) attempt",
            "exploit_attempt": "Possible exploit or shellcode activity",
            "base64_command": "Obfuscated command via base64 (common in attacks)",
            "crypto_miner": "Cryptocurrency miner activity detected",
            "suspicious_download": "Suspicious remote script/binary download",
            "kernel_panic": "Kernel panic or critical memory corruption",
            "oom_killer": "Out-of-memory killer activated",
            "selinux_denial": "SELinux policy violation",
            "audit_failure": "Auditd anomaly event",
            "windows_failed_logon": "Windows failed logon (Event 4625)",
            "repetitive_error": "Repetitive short error message",
        }.get(rule_id, "Rule match")

    def score_record(self, record: dict[str, Any]) -> tuple[float, list[RuleMatch]]:
        """Return (max_score, all_matches) for the record."""
        matches = self.analyze(record)
        if not matches:
            return 0.0, []
        max_score = max(m.score for m in matches)
        return max_score, matches
