"""
Pre-remediation backup utilities.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any


class RemediationBackup:
    """Create and restore backups before remediation actions."""

    def __init__(self, backup_dir: str = "./data/remediate/backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create_snapshot(
        self,
        action_id: str,
        target: str,
        files: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        ts = int(time.time())
        snap_id = f"{action_id}_{ts}"
        snap_path = self.backup_dir / snap_id
        snap_path.mkdir(parents=True, exist_ok=True)

        copied = []
        for fpath in files or []:
            src = Path(fpath)
            if src.exists() and src.is_file():
                dest = snap_path / src.name
                shutil.copy2(src, dest)
                copied.append(str(dest))

        manifest = {
            "id": snap_id,
            "action_id": action_id,
            "target": target,
            "files": copied,
            "metadata": metadata or {},
            "created_at": ts,
        }
        (snap_path / "manifest.json").write_text(json.dumps(manifest, indent=2))
        return manifest

    def list_snapshots(self, action_id: str | None = None) -> list[dict[str, Any]]:
        snaps = []
        for d in sorted(self.backup_dir.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            manifest_path = d / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = json.loads(manifest_path.read_text())
            if action_id and manifest.get("action_id") != action_id:
                continue
            snaps.append(manifest)
        return snaps

    def restore(self, snapshot_id: str) -> dict[str, Any]:
        snap_path = self.backup_dir / snapshot_id
        manifest_path = snap_path / "manifest.json"
        if not manifest_path.exists():
            return {"status": "error", "reason": "snapshot not found"}

        manifest = json.loads(manifest_path.read_text())
        restored = []
        for f in manifest.get("files", []):
            src = Path(f)
            if src.exists():
                restored.append(str(src))
        return {"status": "restored", "snapshot_id": snapshot_id, "files": restored}