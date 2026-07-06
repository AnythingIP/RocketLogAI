#!/usr/bin/env python3
"""Clean a RocketLogAI install directory — remove junk and sync with official layout.

Usage:
    python scripts/rla_cleanup.py INSTALL_DIR [--source SOURCE_TREE] [--fix] [--dry-run]

With --source (repo or fresh clone), stale code under logsentinel/ and templates/
is removed so only current release files remain.
"""

from __future__ import annotations

import argparse
import fnmatch
import shutil
import sys
from pathlib import Path

# Top-level names allowed in a production install directory
ALLOWED_TOP_LEVEL = {
    "logsentinel",
    "templates",
    "scripts",
    "data",
    "backups",
    ".venv",
    "helm",
    "tests",
    "docs",
    "config.yaml",
    "example-config.yaml",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
    ".install-type",
    "start-rocketlogai.bat",
    "start-rocketlogai.ps1",
    "start-rocketlogai.sh",
    "GeoLite2-City.mmdb",
    "INSTALL.md",
    "README.md",
    "LICENSE",
    "rocketlogai.service",
    ".gitignore",  # harmless if copied; not required in prod install
}

# Always remove — never belong in a production install folder
REMOVE_TOP_LEVEL = {
    "RocketLogAI_Ver1.0",
    ".git",
    ".github",
    "dist",
    "COMMIT_MESSAGE.md",
    "errors.txt",
    "TESTING.md",
    "USAGE.md",
    "CONVERSATIONAL_DEVICE_AUTOMATION.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    ".ruff_cache",
    ".pytest_cache",
    ".DS_Store",
    "Thumbs.db",
    "config",  # legacy folder; config.yaml is canonical
}

# Glob patterns for junk files at install root
REMOVE_GLOBS = (
    "Screenshot*.png",
    "Screenshot*.jpg",
    "*.pyc",
    "*.pyo",
    "*.log",
    "logsentinel.db",
    "logsentinel.log",
    "udpproxy.py",
    "~",
)

SKIP_DIR_NAMES = {"__pycache__", ".pytest_cache", ".ruff_cache", ".git"}
SKIP_PRUNE_ROOTS = {".venv", "venv", "data", "backups"}


def _rel_tree(root: Path) -> set[str]:
    out: set[str] = set()
    if not root.is_dir():
        return out
    for path in root.rglob("*"):
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.is_dir():
            continue
        out.add(path.relative_to(root).as_posix())
    for path in root.rglob("*"):
        if path.is_dir() and any(part in SKIP_DIR_NAMES for part in path.parts):
            continue
        if path.is_dir() and not any(path.iterdir()):
            # track empty dirs via marker
            rel = path.relative_to(root).as_posix()
            if rel:
                out.add(rel + "/")
    return out


def _remove_path(path: Path, dry_run: bool) -> bool:
    if not path.exists():
        return False
    label = path.relative_to(path.anchor) if path.is_absolute() else path
    if dry_run:
        print(f"  would remove: {label}")
        return True
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=False)
    else:
        path.unlink(missing_ok=True)
    print(f"  removed: {label}")
    return True


def _migrate_to_data(install_dir: Path, name: str, dry_run: bool) -> bool:
    src = install_dir / name
    if not src.is_file():
        return False
    data_dir = install_dir / "data"
    dst = data_dir / name
    if dst.exists():
        if dry_run:
            print(f"  would remove duplicate root file (already in data/): {name}")
        else:
            src.unlink(missing_ok=True)
            print(f"  removed duplicate root file (already in data/): {name}")
        return True
    if dry_run:
        print(f"  would move: {name} -> data/{name}")
        return True
    data_dir.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    print(f"  moved: {name} -> data/{name}")
    return True


def _under_skip_root(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return True
    return rel.parts and rel.parts[0] in SKIP_PRUNE_ROOTS


def _clean_pycache(root: Path, dry_run: bool) -> int:
    count = 0
    for path in list(root.rglob("__pycache__")):
        if _under_skip_root(path, root):
            continue
        if dry_run:
            print(f"  would remove: {path.relative_to(root)}")
        else:
            shutil.rmtree(path, ignore_errors=True)
            print(f"  removed: {path.relative_to(root)}")
        count += 1
    for path in list(root.rglob("*.pyc")):
        if _under_skip_root(path, root):
            continue
        if dry_run:
            print(f"  would remove: {path.relative_to(root)}")
        else:
            path.unlink(missing_ok=True)
            print(f"  removed: {path.relative_to(root)}")
        count += 1
    return count


def _prune_tree(install_sub: Path, source_sub: Path, dry_run: bool) -> int:
    if not install_sub.is_dir() or not source_sub.is_dir():
        return 0
    allowed = _rel_tree(source_sub)
    allowed_dirs = {p.rstrip("/") for p in allowed if p.endswith("/")}
    allowed_dirs.update({str(Path(p).parent) for p in allowed if "/" in p})
    allowed_dirs.add("")

    removed = 0
    # deepest paths first
    all_paths = sorted(install_sub.rglob("*"), key=lambda p: len(p.parts), reverse=True)
    for path in all_paths:
        if any(part in SKIP_DIR_NAMES for part in path.parts):
            if path.is_dir():
                if _remove_path(path, dry_run):
                    removed += 1
            elif path.is_file():
                if _remove_path(path, dry_run):
                    removed += 1
            continue
        rel = path.relative_to(install_sub).as_posix()
        if path.is_file():
            if rel not in allowed:
                if _remove_path(path, dry_run):
                    removed += 1
        elif path.is_dir():
            # remove empty stale dirs or dirs not in source
            rel_dir = rel + "/"
            src_dir = source_sub / rel
            if not src_dir.exists():
                if _remove_path(path, dry_run):
                    removed += 1
    return removed


def cleanup(install_dir: Path, source_dir: Path | None = None, dry_run: bool = False) -> int:
    install_dir = install_dir.resolve()
    if not install_dir.is_dir():
        print(f"ERROR: Not a directory: {install_dir}", file=sys.stderr)
        return 1

    actions = 0
    print(f"RocketLogAI install cleanup: {install_dir}")
    if dry_run:
        print("(dry run — no changes)")
    print("")

    print("[1] Migrate misplaced runtime files into data/")
    for name in ("logsentinel.db", "logsentinel.log"):
        if _migrate_to_data(install_dir, name, dry_run):
            actions += 1
    for pattern in ("logsentinel.log.*",):
        for path in install_dir.glob(pattern):
            if path.is_file():
                rel = path.name
                if dry_run:
                    print(f"  would move: {rel} -> data/{rel}")
                    actions += 1
                else:
                    (install_dir / "data").mkdir(parents=True, exist_ok=True)
                    shutil.move(str(path), str(install_dir / "data" / rel))
                    print(f"  moved: {rel} -> data/{rel}")
                    actions += 1

    print("")
    print("[2] Remove known junk and legacy bundles")
    for name in sorted(REMOVE_TOP_LEVEL):
        path = install_dir / name
        if _remove_path(path, dry_run):
            actions += 1

    for entry in install_dir.iterdir():
        for pattern in REMOVE_GLOBS:
            if fnmatch.fnmatch(entry.name, pattern):
                if _remove_path(entry, dry_run):
                    actions += 1
                break

    print("")
    print("[3] Remove unexpected top-level items")
    for entry in sorted(install_dir.iterdir(), key=lambda p: p.name.lower()):
        name = entry.name
        if name in ALLOWED_TOP_LEVEL or name in REMOVE_TOP_LEVEL:
            continue
        if any(fnmatch.fnmatch(name, g) for g in REMOVE_GLOBS):
            continue
        if _remove_path(entry, dry_run):
            actions += 1

    print("")
    print("[4] Purge bytecode caches")
    actions += _clean_pycache(install_dir, dry_run)

    if source_dir:
        source_dir = source_dir.resolve()
        print("")
        print("[5] Sync package trees with source release")
        for sub in ("logsentinel", "templates", "scripts"):
            inst = install_dir / sub
            src = source_dir / sub
            if inst.is_dir() and src.is_dir():
                print(f"  syncing {sub}/")
                actions += _prune_tree(inst, src, dry_run)

    print("")
    if actions == 0:
        print("Install folder is already clean.")
    else:
        print(f"Cleanup complete ({actions} action(s)).")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="RocketLogAI install directory cleanup")
    parser.add_argument("install_dir", help="Installation directory to clean")
    parser.add_argument("--source", help="Source tree (repo) for package sync")
    parser.add_argument("--fix", action="store_true", help="Apply changes (default without --fix is dry-run)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed")
    args = parser.parse_args()

    dry_run = args.dry_run or not args.fix
    if not args.fix and not args.dry_run:
        print("No --fix specified; running in dry-run mode. Pass --fix to apply changes.")
        print("")

    source = Path(args.source) if args.source else None
    return cleanup(Path(args.install_dir), source_dir=source, dry_run=dry_run)


if __name__ == "__main__":
    raise SystemExit(main())