"""
Idempotency guard — prevents duplicate execution of confirmed operations.
=========================================================================
Every confirm-tier operation receives an idempotency key.
Replay with the same key → rejected with the original result.
Keys expire after TTL (default 5 minutes).
"""
from __future__ import annotations
import time
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IdempotencyRecord:
    key: str
    operation: str
    created_at: float
    executed: bool = False
    result: dict = field(default_factory=dict)


class IdempotencyGuard:
    """In-memory idempotency key store with TTL."""

    def __init__(self, ttl_seconds: int = 300):
        self._store: dict[str, IdempotencyRecord] = {}
        self._ttl = ttl_seconds

    def generate_key(self, user_id: str, operation: str, params: dict) -> str:
        """Generate a unique idempotency key from operation context."""
        raw = f"{user_id}|{operation}|{json.dumps(params, sort_keys=True)}|{time.time()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def check_or_record(self, key: str, operation: str) -> Optional[IdempotencyRecord]:
        """Check if key was already used. If not, record it.
        Returns None if new (proceed). Returns record if duplicate (reject).
        """
        self._evict_expired()

        if key in self._store:
            existing = self._store[key]
            if existing.executed:
                return existing  # Duplicate — return original result
            return None  # Key exists but not yet executed (first call in progress)

        self._store[key] = IdempotencyRecord(
            key=key,
            operation=operation,
            created_at=time.time(),
        )
        return None  # New key — allowed

    def mark_executed(self, key: str, result: dict):
        """Mark a key as executed and store the result."""
        if key in self._store:
            self._store[key].executed = True
            self._store[key].result = result

    def _evict_expired(self):
        """Remove expired keys."""
        now = time.time()
        expired = [k for k, v in self._store.items()
                   if now - v.created_at > self._ttl]
        for k in expired:
            del self._store[k]

    def stats(self) -> dict:
        self._evict_expired()
        return {
            "active_keys": len(self._store),
            "ttl_seconds": self._ttl,
            "executed": sum(1 for v in self._store.values() if v.executed),
            "pending": sum(1 for v in self._store.values() if not v.executed),
        }


# Singleton
_guard = IdempotencyGuard()


def get_idempotency_guard() -> IdempotencyGuard:
    return _guard
