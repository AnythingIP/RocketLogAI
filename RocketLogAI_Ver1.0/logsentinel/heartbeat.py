"""
Heartbeat / Deep Service Monitoring for LogSentinel.

This module performs active checks against your servers and services
beyond simple port connectivity:

- TCP reachability
- HTTP response content / version string matching
- SSH banner + version parsing (with "needs update" detection)
- Future: custom command output matching

When a check fails or a service is detected as outdated/vulnerable,
it generates a synthetic "threat" that flows through the normal
LogSentinel pipeline (LLM analysis if desired, alerting, Home Assistant
triggering, human verification, etc.).

This gives you one unified threat + remediation surface.
"""

from __future__ import annotations

import logging
import re
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import HeartbeatMonitor, HeartbeatsConfig

logger = logging.getLogger(__name__)

# Lazy import to avoid circular issues
def _get_geo():
    try:
        from .geo import get_geo_enricher
        return get_geo_enricher()
    except Exception:
        return None


@dataclass
class CheckResult:
    monitor_name: str
    host: str
    success: bool
    message: str
    details: dict[str, Any]
    latency_ms: float | None = None
    remediation_suggested: str | None = None


class HeartbeatMonitorRunner:
    """
    Runs the configured heartbeats and turns problems into threats.
    Loads monitors from both config and database (web-edited monitors win for same name).
    """

    def __init__(self, cfg: HeartbeatsConfig, storage: Any = None):
        self.cfg = cfg
        self.storage = storage
        self._last_run: dict[str, float] = {}
        self._monitors: list = self._load_monitors()

    def _load_monitors(self):
        monitors = list(self.cfg.monitors) if self.cfg and self.cfg.monitors else []
        if self.storage:
            try:
                db_mons = self.storage.get_monitors(enabled_only=True)
                for dbm in db_mons:
                    # Convert DB row to HeartbeatMonitor-like object
                    mon = HeartbeatMonitor(
                        name=dbm["name"],
                        host=dbm["host"],
                        type=dbm.get("type", "tcp"),
                        port=dbm.get("port"),
                        path=dbm.get("path") or "/",
                        expected=dbm.get("expected"),
                        severity=dbm.get("severity", "medium"),
                        remediation_action=dbm.get("remediation_action"),
                        interval_seconds=dbm.get("interval_seconds", 300),
                        enabled=bool(dbm.get("enabled", 1)),
                    )
                    # Override or add from DB
                    existing = next((i for i, m in enumerate(monitors) if m.name == mon.name), None)
                    if existing is not None:
                        monitors[existing] = mon
                    else:
                        monitors.append(mon)
            except Exception as e:
                logger.warning("Failed to load monitors from DB: %s", e)
        return monitors

    def should_run(self, monitor: HeartbeatMonitor) -> bool:
        if not getattr(monitor, 'enabled', True):
            return False
        last = self._last_run.get(monitor.name, 0)
        return (time.time() - last) >= getattr(monitor, 'interval_seconds', 300)

    def run_all(self) -> list[CheckResult]:
        """Run all due monitors. Returns list of results."""
        results = []
        for mon in self._monitors:
            if self.should_run(mon):
                res = self._run_one(mon)
                results.append(res)
                self._last_run[mon.name] = time.time()

                if not res.success or res.remediation_suggested:
                    self._maybe_create_synthetic_threat(mon, res)
        return results

    def _run_one(self, mon: HeartbeatMonitor) -> CheckResult:
        start = time.time()
        try:
            if mon.type == "tcp":
                return self._check_tcp(mon, start)
            elif mon.type == "http":
                return self._check_http(mon, start)
            elif mon.type == "https":
                return self._check_https(mon, start)
            elif mon.type == "ssh_version":
                return self._check_ssh_version(mon, start)
            elif mon.type == "ping":
                return self._check_ping(mon, start)
            else:
                return CheckResult(
                    monitor_name=mon.name,
                    host=mon.host,
                    success=False,
                    message=f"Unknown monitor type: {mon.type}",
                    details={},
                )
        except Exception as e:
            latency = (time.time() - start) * 1000
            return CheckResult(
                monitor_name=mon.name,
                host=mon.host,
                success=False,
                message=str(e),
                details={"exception": str(type(e))},
                latency_ms=latency,
            )

    def _check_tcp(self, mon: HeartbeatMonitor, start: float) -> CheckResult:
        port = mon.port or 22
        try:
            with socket.create_connection((mon.host, port), timeout=8):
                latency = (time.time() - start) * 1000
                return CheckResult(
                    monitor_name=mon.name,
                    host=mon.host,
                    success=True,
                    message=f"TCP {port} reachable",
                    details={"port": port},
                    latency_ms=latency,
                )
        except Exception as e:
            return CheckResult(
                monitor_name=mon.name,
                host=mon.host,
                success=False,
                message=f"TCP connect to {port} failed: {e}",
                details={"port": port},
            )

    def _check_http(self, mon: HeartbeatMonitor, start: float) -> CheckResult:
        port = mon.port or 80
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{mon.host}:{port}{mon.path}"

        try:
            with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                latency = (time.time() - start) * 1000

                body = resp.text[:2000]
                headers = dict(resp.headers)

                success = True
                message = f"HTTP {resp.status_code}"

                if mon.expected:
                    haystack = (body + " " + str(headers)).lower()
                    if mon.expected.lower() not in haystack:
                        success = False
                        message = f"HTTP {resp.status_code} - expected string not found: {mon.expected}"

                return CheckResult(
                    monitor_name=mon.name,
                    host=mon.host,
                    success=success,
                    message=message,
                    details={
                        "status_code": resp.status_code,
                        "url": str(resp.url),
                        "headers": dict(resp.headers),
                    },
                    latency_ms=latency,
                )
        except Exception as e:
            return CheckResult(
                monitor_name=mon.name,
                host=mon.host,
                success=False,
                message=f"HTTP request failed: {e}",
                details={"url": url},
            )

    def _check_ssh_version(self, mon: HeartbeatMonitor, start: float) -> CheckResult:
        """Connect to SSH and read the banner. Check against expected version."""
        port = mon.port or 22
        try:
            sock = socket.create_connection((mon.host, port), timeout=8)
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()

            latency = (time.time() - start) * 1000

            # Common OpenSSH banner: SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5
            version_match = re.search(r"OpenSSH[ _-](\d+\.\d+)", banner, re.I)
            current_version = version_match.group(1) if version_match else banner

            success = True
            remediation = None
            message = f"SSH banner: {banner}"

            if mon.expected:
                # User can put e.g. "9.6" or "OpenSSH_9.6"
                if mon.expected.lower() not in banner.lower():
                    success = False
                    message = f"SSH version outdated or unexpected. Got: {banner}"
                    remediation = mon.remediation_action or "update_ssh"

            return CheckResult(
                monitor_name=mon.name,
                host=mon.host,
                success=success,
                message=message,
                details={"banner": banner, "parsed_version": current_version},
                latency_ms=latency,
                remediation_suggested=remediation,
            )
        except Exception as e:
            return CheckResult(
                monitor_name=mon.name,
                host=mon.host,
                success=False,
                message=f"SSH banner check failed: {e}",
                details={"port": port},
            )

    def _check_ping(self, mon: HeartbeatMonitor, start: float) -> CheckResult:
        """Cross-platform ping using the system ping binary (safe, no raw sockets needed)."""
        import platform
        import subprocess
        import re

        host = mon.host
        is_windows = platform.system().lower().startswith("win")

        # Build command
        if is_windows:
            cmd = ["ping", "-n", "1", "-w", "3000", host]
        else:
            # macOS / Linux — -W is deadline on Linux, -t on mac. -c 1 is universal.
            cmd = ["ping", "-c", "1", "-W", "3", host]  # Linux-friendly; mac ignores -W or treats as -t

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            latency = (time.time() - start) * 1000
            out = (proc.stdout or "") + (proc.stderr or "")

            # Try to extract latency from output (works for most Unix + Windows English)
            latency_match = re.search(r"time[=<]?\s*([\d.]+)\s*ms", out, re.I)
            latency_ms = float(latency_match.group(1)) if latency_match else None

            if proc.returncode == 0:
                return CheckResult(
                    monitor_name=mon.name,
                    host=host,
                    success=True,
                    message=f"Ping OK" + (f" ({latency_ms:.1f} ms)" if latency_ms else ""),
                    details={"host": host, "raw_output": out[:800]},
                    latency_ms=latency_ms or latency,
                )
            else:
                return CheckResult(
                    monitor_name=mon.name,
                    host=host,
                    success=False,
                    message=f"Ping failed (exit {proc.returncode})",
                    details={"host": host, "raw_output": out[:800]},
                )
        except subprocess.TimeoutExpired:
            return CheckResult(
                monitor_name=mon.name,
                host=host,
                success=False,
                message="Ping timed out",
                details={"host": host},
            )
        except Exception as e:
            return CheckResult(
                monitor_name=mon.name,
                host=host,
                success=False,
                message=f"Ping error: {e}",
                details={"host": host},
            )

    def _check_https(self, mon: HeartbeatMonitor, start: float) -> CheckResult:
        """Deep HTTPS + TLS inspection.
        - Full TLS handshake
        - Leaf certificate fingerprint (SHA-256), subject, issuer, validity
        - Negotiated TLS version + cipher
        - Basic red-flag detection (expired, expires soon, weak signature, old TLS)
        This is the foundation for "prove the site is who it claims and detect changes".
        """
        import ssl
        import socket
        import hashlib
        from datetime import datetime, timezone

        port = mon.port or 443
        host = mon.host
        path = mon.path or "/"

        details: dict[str, Any] = {"port": port, "url": f"https://{host}:{port}{path}"}
        red_flags: list[str] = []

        try:
            # 1. Low-level TLS handshake to get the real peer certificate
            context = ssl.create_default_context()
            # We still want to inspect even if verification would fail in strict mode
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    # Get the leaf cert in DER form
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        sha256_fp = hashlib.sha256(der_cert).hexdigest()
                        details["cert_sha256"] = sha256_fp
                        details["cert_fingerprint"] = f"SHA256:{sha256_fp}"

                    # Parsed form (may be limited without cryptography)
                    try:
                        parsed = ssock.getpeercert()
                        if parsed:
                            details["cert_subject"] = parsed.get("subject")
                            details["cert_issuer"] = parsed.get("issuer")
                            details["cert_not_before"] = parsed.get("notBefore")
                            details["cert_not_after"] = parsed.get("notAfter")
                            details["cert_san"] = parsed.get("subjectAltName")

                            # Expiry analysis
                            not_after = parsed.get("notAfter")
                            if not_after:
                                try:
                                    # Typical format: 'May  8 12:00:00 2027 GMT'
                                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                                    days_left = (dt - datetime.now(timezone.utc)).days
                                    details["cert_days_until_expiry"] = days_left
                                    if days_left < 0:
                                        red_flags.append("Certificate is EXPIRED")
                                    elif days_left < 14:
                                        red_flags.append(f"Certificate expires in only {days_left} days")
                                except Exception:
                                    pass
                    except Exception:
                        pass

                    details["tls_version"] = tls_version
                    details["cipher"] = cipher[0] if cipher else None

                    # Basic red flags on protocol / cipher
                    if tls_version and tls_version in ("TLSv1", "TLSv1.1"):
                        red_flags.append(f"Old TLS version negotiated: {tls_version}")
                    if cipher and any(x in (cipher[0] or "").upper() for x in ("RC4", "DES", "MD5", "NULL")):
                        red_flags.append("Weak cipher negotiated")

            # 2. Actual HTTP request over the verified TLS context (we already did the handshake)
            # Use httpx with verify=False because we did our own deeper inspection above.
            url = f"https://{host}:{port}{path}"
            with httpx.Client(timeout=12, follow_redirects=True, verify=False) as client:
                resp = client.get(url)
                latency = (time.time() - start) * 1000

                body = resp.text[:2500]
                success = True
                message = f"HTTPS {resp.status_code}"

                if mon.expected:
                    haystack = (body + " " + str(resp.headers)).lower()
                    if mon.expected.lower() not in haystack:
                        success = False
                        message = f"HTTPS {resp.status_code} — expected string not found"

                if red_flags:
                    success = False  # treat red flags as a failing check for visibility
                    message = f"HTTPS {resp.status_code} — RED FLAGS: {'; '.join(red_flags)}"

                details.update({
                    "status_code": resp.status_code,
                    "final_url": str(resp.url),
                    "red_flags": red_flags,
                    "headers_sample": {k: v for k, v in list(resp.headers.items())[:8]},
                })

                # Change detection hook (we surface the fingerprint; higher layers / AI can compare over time)
                if red_flags:
                    details["cert_red_flags"] = red_flags

                return CheckResult(
                    monitor_name=mon.name,
                    host=host,
                    success=success,
                    message=message,
                    details=details,
                    latency_ms=latency,
                    remediation_suggested="review_certificate" if red_flags else None,
                )

        except Exception as e:
            latency = (time.time() - start) * 1000
            return CheckResult(
                monitor_name=mon.name,
                host=host,
                success=False,
                message=f"HTTPS/TLS check failed: {e}",
                details=details,
                latency_ms=latency,
            )

    def _maybe_create_synthetic_threat(self, mon: HeartbeatMonitor, result: CheckResult) -> None:
        """
        Turn a failed/outdated heartbeat into a normal threat record.
        This lets the entire existing pipeline (alerting, HA, human review, LLM) handle it.
        """
        if not self.storage:
            return

        # Create a synthetic threat description
        desc = f"Monitor '{mon.name}' on {mon.host}: {result.message}"

        threat = {
            "severity": mon.severity,
            "score": 8.5 if not result.success else 6.0,
            "description": desc,
            "hostname": mon.host,
            "appname": "heartbeat",
            "recommended_action": result.remediation_suggested or "Investigate service health",
            "evidence": [result.details],
            "source_ip": None,
        }

        # Apply offline geo if we can derive an IP (for remote monitors)
        geo = _get_geo()
        if geo and mon.host:
            try:
                # Try to resolve host to IP for geo lookup
                import socket as _socket
                ip = _socket.gethostbyname(mon.host)
                g = geo.enrich(ip)
                if g:
                    threat["source_ip"] = ip
                    threat.update({
                        "geo_country": g.get("country"),
                        "geo_city": g.get("city"),
                        "geo_lat": g.get("lat"),
                        "geo_lon": g.get("lon"),
                        "geo_accuracy": g.get("accuracy"),
                    })
            except Exception:
                pass

        try:
            analysis_id = self.storage.create_analysis(model="heartbeat")
            self.storage.finish_analysis(
                analysis_id=analysis_id,
                summary=f"Heartbeat failure for {mon.name}",
                threats=[threat],
            )
            logger.info("Created synthetic threat from heartbeat failure: %s", mon.name)
        except Exception as e:
            logger.error("Failed to create synthetic heartbeat threat: %s", e)
