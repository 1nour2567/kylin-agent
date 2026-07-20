"""
Lightweight rollback — automatic backup before write, restore on demand.
=========================================================================
Every file-modifying operation snapshots the target before execution.
Backups stored under /tmp/kylin-agent/rollback/ with SHA256 integrity.
Supports restore, list, and retention-based cleanup.
"""
from __future__ import annotations
import os
import shutil
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


ROLLBACK_DIR = "/tmp/kylin-agent/rollback"
MANIFEST_FILE = os.path.join(ROLLBACK_DIR, "manifest.json")
RETENTION_DAYS = 7  # Keep rollback snapshots for 7 days


@dataclass
class RollbackEntry:
    entry_id: str
    original_path: str
    operation: str          # "truncate", "delete", "write", "chmod"
    backup_path: str
    original_size: int
    backup_hash: str
    timestamp: str
    restored: bool = False


class RollbackManager:
    """Pre-operation backup + post-operation restore capability."""

    def __init__(self):
        os.makedirs(ROLLBACK_DIR, exist_ok=True)
        if not os.path.exists(MANIFEST_FILE):
            self._write_manifest([])

    # ── Manifest ──

    def _read_manifest(self) -> list[dict]:
        try:
            with open(MANIFEST_FILE, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _write_manifest(self, entries: list[dict]):
        with open(MANIFEST_FILE, "w") as f:
            json.dump(entries, f, indent=2)

    # ── Snapshot ──

    def snapshot(self, path: str, operation: str = "write") -> Optional[RollbackEntry]:
        """Backup a file before modifying it. Returns entry if snapshot created."""
        abs_path = os.path.abspath(os.path.expanduser(path))

        if not os.path.exists(abs_path):
            return None  # Nothing to backup

        if not os.path.isfile(abs_path):
            return None  # Only snapshot regular files

        # Skip small or temporary files
        size = os.path.getsize(abs_path)
        if size < 1:
            return None

        # Create backup
        entry_id = f"{int(time.time() * 1000)}_{os.path.basename(abs_path)}"
        backup_path = os.path.join(ROLLBACK_DIR, entry_id)

        try:
            shutil.copy2(abs_path, backup_path)
        except (OSError, IOError):
            return None

        # Hash for integrity
        sha = hashlib.sha256()
        with open(backup_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha.update(chunk)
        backup_hash = sha.hexdigest()[:16]

        entry = RollbackEntry(
            entry_id=entry_id,
            original_path=abs_path,
            operation=operation,
            backup_path=backup_path,
            original_size=size,
            backup_hash=backup_hash,
            timestamp=datetime.now().isoformat(),
        )

        # Persist
        manifest = self._read_manifest()
        manifest.append({
            "entry_id": entry.entry_id,
            "original_path": entry.original_path,
            "operation": entry.operation,
            "backup_path": entry.backup_path,
            "original_size": entry.original_size,
            "backup_hash": entry.backup_hash,
            "timestamp": entry.timestamp,
            "restored": False,
        })
        self._write_manifest(manifest)

        return entry

    # ── Restore ──

    def restore(self, entry_id: str) -> dict:
        """Restore a file from its rollback snapshot."""
        manifest = self._read_manifest()
        for entry in manifest:
            if entry["entry_id"] == entry_id and not entry["restored"]:
                backup_path = entry["backup_path"]
                original_path = entry["original_path"]

                if not os.path.exists(backup_path):
                    return {"success": False, "error": "Backup file not found — may have been cleaned up"}

                try:
                    # Verify hash before restore
                    sha = hashlib.sha256()
                    with open(backup_path, "rb") as f:
                        for chunk in iter(lambda: f.read(8192), b""):
                            sha.update(chunk)
                    if sha.hexdigest()[:16] != entry["backup_hash"]:
                        return {"success": False, "error": "Backup integrity check failed — hash mismatch"}

                    # Restore
                    os.makedirs(os.path.dirname(original_path), exist_ok=True)
                    shutil.copy2(backup_path, original_path)
                    entry["restored"] = True
                    self._write_manifest(manifest)

                    return {
                        "success": True,
                        "original_path": original_path,
                        "restored_size": entry["original_size"],
                        "operation_reversed": entry["operation"],
                    }
                except (OSError, IOError) as e:
                    return {"success": False, "error": str(e)}

        return {"success": False, "error": f"Entry {entry_id} not found or already restored"}

    def restore_last(self, path: str) -> dict:
        """Restore the most recent backup for a given file path."""
        abs_path = os.path.abspath(os.path.expanduser(path))
        manifest = self._read_manifest()
        for entry in reversed(manifest):
            if entry["original_path"] == abs_path and not entry["restored"]:
                return self.restore(entry["entry_id"])
        return {"success": False, "error": f"No unrestored backup found for {abs_path}"}

    # ── List ──

    def list_entries(self, limit: int = 50) -> list[dict]:
        """List recent rollback entries."""
        manifest = self._read_manifest()
        return manifest[-limit:]

    def list_restorable(self) -> list[dict]:
        """List all unrestored entries."""
        return [e for e in self._read_manifest() if not e["restored"]]

    # ── Cleanup ──

    def cleanup(self, older_than_days: int = RETENTION_DAYS) -> dict:
        """Remove expired backups and their manifest entries."""
        cutoff = datetime.now() - timedelta(days=older_than_days)
        manifest = self._read_manifest()
        removed = 0
        freed_bytes = 0
        new_manifest = []

        for entry in manifest:
            try:
                ts = datetime.fromisoformat(entry["timestamp"])
            except (ValueError, KeyError):
                new_manifest.append(entry)
                continue

            if ts < cutoff:
                backup_path = entry["backup_path"]
                if os.path.exists(backup_path):
                    freed_bytes += os.path.getsize(backup_path)
                    os.remove(backup_path)
                removed += 1
            else:
                new_manifest.append(entry)

        self._write_manifest(new_manifest)
        return {"removed": removed, "freed_bytes": freed_bytes, "remaining": len(new_manifest)}

    # ── Stats ──

    def stats(self) -> dict:
        """Summary statistics for the rollback store."""
        manifest = self._read_manifest()
        total_size = sum(e.get("original_size", 0) for e in manifest)
        restored = sum(1 for e in manifest if e.get("restored"))
        pending = len(manifest) - restored
        return {
            "total_snapshots": len(manifest),
            "restored": restored,
            "pending": pending,
            "total_size_bytes": total_size,
            "storage_path": ROLLBACK_DIR,
            "retention_days": RETENTION_DAYS,
        }
