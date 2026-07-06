#!/usr/bin/env python3
"""RocketLogAI server sign-off test — pages, APIs, HA device monitors."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("Install requests: pip install requests", file=sys.stderr)
    sys.exit(2)

# Sidebar pages from templates/base.html
PAGES = [
    "/",
    "/threats",
    "/analyses",
    "/monitors",
    "/activity",
    "/daily",
    "/assistant",
    "/shield",
    "/agents",
    "/system-health",
    "/logs",
    "/devices",
    "/maps",
    "/integrations",
    "/config",
    "/automation",
    "/users",
]

APIS = [
    ("GET", "/api/system/diagnostics"),
    ("GET", "/api/devices"),
    ("GET", "/api/monitors"),
    ("GET", "/api/threats"),
    ("GET", "/api/analyses"),
    ("GET", "/api/logs"),
    ("GET", "/api/server-activity"),
    ("GET", "/api/charts/severity"),
    ("GET", "/api/charts/activity"),
    ("GET", "/api/automation/preferences"),
    ("GET", "/api/automation/custom-rules"),
    ("GET", "/api/assistant/session"),
    ("GET", "/api/v2/status"),
    ("GET", "/api/v2/audit"),
    ("GET", "/api/config/running"),
]

MONITOR_PREFIX = "signoff-"


@dataclass
class Result:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append(Result(name, ok, detail))
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f" — {detail}"
        print(line)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.ok)


def login(session: requests.Session, base: str, user: str, password: str) -> bool:
    r = session.post(
        urljoin(base, "/login"),
        data={"username": user, "password": password},
        allow_redirects=False,
        timeout=15,
    )
    cookies = session.cookies.get_dict()
    return r.status_code in (302, 303) and (
        "logsentinel_session" in cookies or any("session" in k for k in cookies)
    )


def slug(name: str, ip: str) -> str:
    short = re.sub(r"[^a-zA-Z0-9]+", "-", (name or ip).lower()).strip("-")[:24]
    return f"{MONITOR_PREFIX}ping-{short}"


def pick_ha_devices(devices: list[dict[str, Any]], limit: int = 6) -> list[dict[str, Any]]:
    """Prefer HA-linked internal devices with stable IPs."""
    candidates = []
    for d in devices:
        ip = d.get("ip") or ""
        if not ip.startswith("192.168."):
            continue
        if not d.get("ha_name") and not d.get("ha_entity_id"):
            continue
        candidates.append(d)
    # Sort by last_seen desc, dedupe by IP
    seen: set[str] = set()
    picked = []
    for d in sorted(candidates, key=lambda x: x.get("last_seen") or "", reverse=True):
        ip = d["ip"]
        if ip in seen:
            continue
        seen.add(ip)
        picked.append(d)
        if len(picked) >= limit:
            break
    return picked


def ensure_monitors(
    session: requests.Session,
    base: str,
    devices: list[dict[str, Any]],
    existing_names: set[str],
    report: Report,
) -> list[str]:
    created: list[str] = []
    for d in pick_ha_devices(devices, limit=6):
        ip = d["ip"]
        label = d.get("ha_name") or ip
        name = slug(label, ip)
        if name in existing_names:
            report.add(f"monitor exists: {name}", True, ip)
            created.append(name)
            continue
        payload = {
            "name": name,
            "host": ip,
            "type": "ping",
            "severity": "low",
            "interval_seconds": 600,
            "enabled": True,
        }
        r = session.post(urljoin(base, "/api/monitors"), json=payload, timeout=15)
        ok = r.status_code == 200 and "error" not in (r.json() if r.text else {})
        detail = ip
        if not ok:
            try:
                detail = r.json().get("error") or r.text[:120]
            except Exception:
                detail = r.text[:120]
        report.add(f"create monitor: {name}", ok, detail)
        if ok:
            created.append(name)
            existing_names.add(name)
    return created


def run_monitors(session: requests.Session, base: str, names: list[str], report: Report) -> None:
    for name in names:
        if not name.startswith(MONITOR_PREFIX):
            continue
        r = session.post(urljoin(base, f"/api/monitors/{name}/run"), timeout=60)
        ok = False
        detail = ""
        try:
            body = r.json()
            ok = bool(body.get("success"))
            result = body.get("result") or {}
            detail = result.get("message") or body.get("error") or ""
            if result.get("success") is False:
                ok = False
        except Exception:
            detail = r.text[:120]
        report.add(f"run monitor: {name}", ok, detail[:100])


def test_assistant_ping(session: requests.Session, base: str, report: Report) -> None:
    r = session.post(
        urljoin(base, "/api/assistant/ask"),
        json={"message": "ping 192.168.20.1"},
        timeout=30,
    )
    ok = r.status_code == 200
    detail = ""
    try:
        body = r.json()
        mode = body.get("mode") or body.get("response_mode")
        detail = f"mode={mode}"
        if body.get("action_plan") or mode == "action_plan":
            ok = True
        elif body.get("reply") or body.get("answer"):
            ok = True
    except Exception:
        detail = r.text[:80]
    report.add("assistant: ping gateway", ok, detail)


def test_ha(session: requests.Session, base: str, report: Report) -> None:
    r = session.post(urljoin(base, "/api/test/ha"), json={}, timeout=20)
    ok = r.status_code == 200
    detail = ""
    try:
        body = r.json()
        ok = bool(body.get("ok") or body.get("success") or body.get("connected"))
        detail = body.get("message") or body.get("error") or str(body)[:80]
    except Exception:
        detail = r.text[:80]
    report.add("integrations: HA test", ok, detail)


def main() -> int:
    p = argparse.ArgumentParser(description="RocketLogAI sign-off test")
    p.add_argument("--base", default="https://192.168.20.134:8788", help="Server base URL")
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default="admin")
    p.add_argument("--insecure", action="store_true", default=True)
    p.add_argument("--skip-monitors", action="store_true")
    args = p.parse_args()

    base = args.base.rstrip("/") + "/"
    report = Report()

    session = requests.Session()
    session.verify = not args.insecure

    print(f"\nRocketLogAI sign-off — {base}\n")

    if not login(session, base, args.user, args.password):
        print("  [FAIL] login")
        return 1
    report.add("login", True)

    for path in PAGES:
        r = session.get(urljoin(base, path.lstrip("/")), timeout=20)
        ok = r.status_code == 200 and "text/html" in (r.headers.get("content-type") or "")
        report.add(f"page: {path}", ok, f"HTTP {r.status_code}")

    for method, path in APIS:
        r = session.request(method, urljoin(base, path.lstrip("/")), timeout=30)
        ok = r.status_code == 200
        detail = f"HTTP {r.status_code}"
        if ok:
            try:
                body = r.json()
                if "error" in body and body["error"]:
                    ok = False
                    detail = str(body["error"])[:80]
            except Exception:
                pass
        report.add(f"api: {path}", ok, detail)

    test_assistant_ping(session, base, report)
    test_ha(session, base, report)

    if not args.skip_monitors:
        dev_r = session.get(urljoin(base, "api/devices"), timeout=20)
        mon_r = session.get(urljoin(base, "api/monitors"), timeout=20)
        devices = []
        existing = set()
        if dev_r.status_code == 200:
            devices = dev_r.json().get("devices") or []
            report.add("HA devices loaded", True, f"{len(devices)} total")
        if mon_r.status_code == 200:
            existing = {m["name"] for m in mon_r.json().get("monitors") or []}

        names = ensure_monitors(session, base, devices, existing, report)
        time.sleep(0.5)
        run_monitors(session, base, names, report)

    print(f"\n{'=' * 50}")
    print(f"  PASSED: {report.passed}   FAILED: {report.failed}")
    print(f"{'=' * 50}\n")

    if report.failed:
        print("Failed checks:")
        for r in report.results:
            if not r.ok:
                print(f"  - {r.name}: {r.detail}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())