#!/usr/bin/env python3
"""Find and select the best Python interpreter for RocketLogAI.

Recommended: Python 3.12 (full AI Operator + all v2 extras on Windows).

Usage:
    python scripts/rla_python.py                    # JSON best interpreter
    python scripts/rla_python.py --ask              # Interactive pick
    python scripts/rla_python.py --list             # List all found
    python scripts/rla_python.py --has 3.12         # Exit 0 if 3.12 available
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from typing import Any

PREFERRED_TAGS = ("3.12", "3.11", "3.10")
RECOMMENDED_TAG = "3.12"
AI_OPERATOR_MAX = (3, 12)


def _parse_version(version: str) -> tuple[int, int]:
    parts = version.strip().split(".")
    return int(parts[0]), int(parts[1])


def _version_le(version: str, maximum: tuple[int, int]) -> bool:
    major, minor = _parse_version(version)
    return (major, minor) <= maximum


def _run_probe(cmd: list[str]) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(
            cmd
            + [
                "-c",
                "import sys; print(sys.executable); "
                "print(f'{sys.version_info[0]}.{sys.version_info[1]}')",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    lines = [ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    version = lines[1]
    major, minor = _parse_version(version)
    if major != 3 or minor < 10:
        return None
    tag = f"{major}.{minor}"
    return {
        "command": cmd,
        "executable": lines[0],
        "version": version,
        "tag": tag,
        "recommended": tag == RECOMMENDED_TAG,
        "ai_operator_full": _version_le(version, AI_OPERATOR_MAX),
    }


def discover_interpreters() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(entry: dict[str, Any] | None) -> None:
        if not entry:
            return
        key = entry["executable"].lower()
        if key in seen:
            return
        seen.add(key)
        found.append(entry)

    system = platform.system()

    if system == "Windows" and shutil.which("py"):
        for tag in PREFERRED_TAGS:
            add(_run_probe(["py", f"-{tag}"]))
        for name in ("python", "python3"):
            if shutil.which(name):
                add(_run_probe([name]))

    else:
        for name in ("python3.12", "python3.11", "python3.10", "python3", "python"):
            if shutil.which(name):
                add(_run_probe([name]))

    def sort_key(item: dict[str, Any]) -> tuple[int, int, int]:
        tag = item["tag"]
        if tag == RECOMMENDED_TAG:
            return (0, 0, 0)
        if tag in PREFERRED_TAGS:
            return (1, PREFERRED_TAGS.index(tag), 0)
        major, minor = _parse_version(tag)
        return (2, -major, -minor)

    found.sort(key=sort_key)
    return found


def select_best(ask: bool = False) -> dict[str, Any] | None:
    interpreters = discover_interpreters()
    if not interpreters:
        return None

    if ask:
        err = sys.stderr
        print("RocketLogAI Python version", file=err)
        print("Recommended: Python 3.12 (full AI Operator + all extras on Windows)", file=err)
        print("", file=err)
        for idx, item in enumerate(interpreters, start=1):
            flags = []
            if item["recommended"]:
                flags.append("recommended")
            if item["ai_operator_full"]:
                flags.append("full AI Operator")
            else:
                flags.append("core only - AI Operator may be skipped")
            label = ", ".join(flags)
            cmd = " ".join(item["command"])
            print(f"  {idx}) Python {item['version']}  ({cmd})  [{label}]", file=err)
        print("", file=err)
        default = 1
        choice = input(f"Select Python [1-{len(interpreters)}] (default {default}): ").strip()
        if not choice:
            choice = str(default)
        try:
            pick = int(choice) - 1
            if 0 <= pick < len(interpreters):
                selected = interpreters[pick]
                if _run_probe(selected["command"]) is None:
                    cmd = " ".join(selected["command"])
                    print(f"ERROR: Python launcher failed: {cmd}", file=err)
                    return None
                return selected
        except ValueError:
            pass
        print("Invalid choice, using recommended interpreter.", file=err)

    for item in interpreters:
        if item["tag"] == RECOMMENDED_TAG:
            selected = item
            break
    else:
        selected = interpreters[0]

    if _run_probe(selected["command"]) is None:
        cmd = " ".join(selected["command"])
        print(
            f"ERROR: Python launcher failed: {cmd}",
            file=sys.stderr,
        )
        if selected["tag"] != RECOMMENDED_TAG:
            print(
                "Install Python 3.12 from https://www.python.org/downloads/release/python-3120/",
                file=sys.stderr,
            )
        return None

    return selected


def main() -> int:
    parser = argparse.ArgumentParser(description="RocketLogAI Python selector")
    parser.add_argument("--ask", action="store_true", help="Interactive selection")
    parser.add_argument("--list", action="store_true", help="List interpreters as JSON array")
    parser.add_argument("--has", metavar="TAG", help="Exit 0 if TAG is available (e.g. 3.12)")
    args = parser.parse_args()

    interpreters = discover_interpreters()

    if args.list:
        print(json.dumps(interpreters, indent=2))
        return 0

    if args.has:
        ok = any(item["tag"] == args.has for item in interpreters)
        return 0 if ok else 1

    selected = select_best(ask=args.ask)
    if not selected:
        print("ERROR: Python 3.10+ not found.", file=sys.stderr)
        print("Install Python 3.12: https://www.python.org/downloads/", file=sys.stderr)
        return 1

    print(json.dumps(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())