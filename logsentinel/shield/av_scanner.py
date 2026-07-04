"""
AV scanner on decrypted traffic — signature + heuristic detection.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any


# EICAR test string and common malware signatures (educational / detection patterns)
MALWARE_SIGNATURES = {
    "eicar": b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
    "powershell_encoded": b"-EncodedCommand",
    "mimikatz": b"mimikatz",
}


class AVScanner:
    """Lightweight AV scanner for decrypted network payloads."""

    def __init__(self, quarantine_dir: str = "./data/shield/quarantine"):
        self.quarantine_dir = quarantine_dir
        self._scans: list[dict[str, Any]] = []

    def scan_payload(self, data: bytes, source_ip: str = "", filename: str = "") -> dict[str, Any]:
        threats = []
        for name, sig in MALWARE_SIGNATURES.items():
            if sig in data:
                threats.append({"signature": name, "severity": "critical"})

        # Heuristic: high entropy + executable headers
        if data[:2] == b"MZ" or data[:4] == b"\x7fELF":
            threats.append({"signature": "executable_transfer", "severity": "medium"})

        sha256 = hashlib.sha256(data).hexdigest()
        clean = len(threats) == 0
        result = {
            "clean": clean,
            "threats": threats,
            "sha256": sha256,
            "source_ip": source_ip,
            "filename": filename,
            "size": len(data),
            "ts": time.time(),
        }
        self._scans.append(result)
        if len(self._scans) > 500:
            self._scans = self._scans[-250:]
        return result

    def scan_http_body(self, body: str | bytes, **kwargs: Any) -> dict[str, Any]:
        if isinstance(body, str):
            body = body.encode("utf-8", errors="replace")
        return self.scan_payload(body, **kwargs)

    def recent_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._scans[-limit:]

    def status(self) -> dict[str, Any]:
        infected = sum(1 for s in self._scans if not s.get("clean"))
        return {"total_scans": len(self._scans), "threats_detected": infected}