#!/usr/bin/env python3
"""Backup and restore RocketLogAI user data (config, database, geo DB).

Usage:
    python scripts/rla_backup.py INSTALL_DIR
    python scripts/rla_backup.py INSTALL_DIR --restore BACKUP_DIR
    python scripts/rla_backup.py INSTALL_DIR --list
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

BACKUP_ITEMS = (
    "config.yaml",
    "data",
    "GeoLite2-City.mmdb",
    ".install-type",
    "config",
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def backup(install_dir: Path, label: str = "pre-upgrade") -> Path:
    install_dir = install_dir.resolve()
    backups_root = install_dir / "backups"
    backups_root.mkdir(parents=True, exist_ok=True)
    dest = backups_root / f"{label}-{_timestamp()}"
    dest.mkdir(parents=True, exist_ok=True)

    copied: list[str] = []
    for name in BACKUP_ITEMS:
        src = install_dir / name
        if not src.exists():
            continue
        dst = dest / name
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        copied.append(name)

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "install_dir": str(install_dir),
        "label": label,
        "items": copied,
    }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Backup created: {dest}")
    for item in copied:
        print(f"  - {item}")
    if not copied:
        print("  (no user data files found yet — safe for fresh installs)")
    return dest


def restore(install_dir: Path, backup_dir: Path) -> None:
    install_dir = install_dir.resolve()
    backup_dir = backup_dir.resolve()
    manifest_path = backup_dir / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        items = manifest.get("items", BACKUP_ITEMS)
    else:
        items = list(BACKUP_ITEMS)

    restored: list[str] = []
    for name in items:
        src = backup_dir / name
        if not src.exists():
            continue
        dst = install_dir / name
        if src.is_dir():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        restored.append(name)

    print(f"Restored into {install_dir}")
    for item in restored:
        print(f"  - {item}")
    if not restored:
        print("  (nothing to restore from this backup)")


def list_backups(install_dir: Path) -> list[Path]:
    root = install_dir / "backups"
    if not root.is_dir():
        return []
    return sorted([p for p in root.iterdir() if p.is_dir()], reverse=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="RocketLogAI backup/restore")
    parser.add_argument("install_dir", help="RocketLogAI installation directory")
    parser.add_argument("--restore", metavar="BACKUP_DIR", help="Restore from backup directory")
    parser.add_argument("--list", action="store_true", help="List available backups")
    parser.add_argument("--label", default="pre-upgrade", help="Backup label prefix")
    args = parser.parse_args()

    install_dir = Path(args.install_dir)
    if not install_dir.is_dir():
        print(f"ERROR: Not a directory: {install_dir}", file=sys.stderr)
        return 1

    if args.list:
        backups = list_backups(install_dir)
        if not backups:
            print("No backups found.")
            return 0
        for path in backups:
            print(path)
        return 0

    if args.restore:
        restore(install_dir, Path(args.restore))
        return 0

    backup(install_dir, label=args.label)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())