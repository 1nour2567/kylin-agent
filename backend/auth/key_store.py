"""API key store with SHA256 hashing, role assignment, and JSON persistence.

Each key maps to exactly one user with one role. Keys are stored as SHA256 hashes
so the plain key is never persisted — shown once at creation time only.
"""
import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

from config import settings

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
KEYS_FILE = os.path.join(DATA_DIR, "keys.json")

ROLES = ("admin", "operator", "viewer")


def generate_key() -> str:
    return "kylin_" + secrets.token_hex(16)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class KeyEntry:
    key_id: str
    user_id: str
    role: str
    key_hash: str
    created_at: str = ""
    last_used_at: Optional[str] = None


class KeyStore:
    def __init__(self, path: str = KEYS_FILE):
        self.path = path
        self._keys: Dict[str, KeyEntry] = {}
        self._mtime: float = 0
        self._load()

    def _ensure_fresh(self):
        """Reload from disk if file was modified since last load."""
        try:
            mtime = os.path.getmtime(self.path)
            if mtime > self._mtime:
                self._load()
        except OSError:
            pass

    # ── CRUD ──

    def create_key(self, user_id: str, role: str = "operator") -> str:
        if role not in ROLES:
            raise ValueError(f"Invalid role '{role}'. Must be one of {ROLES}")

        plain_key = generate_key()
        key_hash = hash_key(plain_key)
        key_id = f"key_{secrets.token_hex(4)}"

        entry = KeyEntry(
            key_id=key_id,
            user_id=user_id,
            role=role,
            key_hash=key_hash,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        )
        self._keys[key_hash] = entry
        self._save()
        return plain_key

    def validate(self, key_string: str) -> Optional[dict]:
        self._ensure_fresh()
        if not key_string:
            return None

        # Backward-compat: single API_KEY in .env still works
        api_key = settings.api_key
        if api_key and key_string == api_key:
            return {
                "user_id": "admin",
                "role": "admin",
                "key_id": "key_env",
            }

        key_hash = hash_key(key_string)
        entry = self._keys.get(key_hash)
        if entry is None:
            return None

        entry.last_used_at = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._save()
        return {
            "user_id": entry.user_id,
            "role": entry.role,
            "key_id": entry.key_id,
        }

    def revoke(self, key_id: str) -> bool:
        for key_hash, entry in list(self._keys.items()):
            if entry.key_id == key_id:
                del self._keys[key_hash]
                self._save()
                return True
        return False

    def list_entries(self) -> list:
        return [
            {
                "key_id": e.key_id,
                "user_id": e.user_id,
                "role": e.role,
                "created_at": e.created_at,
                "last_used_at": e.last_used_at,
            }
            for e in self._keys.values()
        ]

    def get_by_key_id(self, key_id: str) -> Optional[KeyEntry]:
        for entry in self._keys.values():
            if entry.key_id == key_id:
                return entry
        return None

    # ── Persistence ──

    def _load(self):
        if not os.path.exists(self.path):
            self._mtime = 0
            return
        try:
            self._mtime = os.path.getmtime(self.path)
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._keys.clear()
            for key_hash, d in data.items():
                self._keys[key_hash] = KeyEntry(**d)
        except (json.JSONDecodeError, TypeError):
            pass

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        data = {kh: asdict(e) for kh, e in self._keys.items()}
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
