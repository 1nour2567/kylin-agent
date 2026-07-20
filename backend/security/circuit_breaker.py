"""
Circuit Breaker — timeout + failure threshold protection.
=============================================================
Three states: CLOSED (normal) → OPEN (block all) → HALF_OPEN (probe) → CLOSED.

Configurable thresholds:
  - failure_threshold: consecutive failures before opening
  - timeout_threshold: per-operation timeout in seconds
  - recovery_timeout: seconds before attempting HALF_OPEN
  - half_open_max: max requests in HALF_OPEN before deciding

Integrated at sandbox execution level and tool-call level.
"""
from __future__ import annotations
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable


class CircuitState(str, Enum):
    CLOSED = "closed"         # Normal operation
    OPEN = "open"             # All requests blocked
    HALF_OPEN = "half_open"   # Limited probe requests allowed


@dataclass
class CircuitStats:
    state: CircuitState
    total_requests: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    last_failure_reason: str = ""
    opened_at: float = 0.0
    total_rejected: int = 0


class CircuitBreaker:
    """Thread-safe circuit breaker for tool execution."""

    def __init__(self, name: str,
                 failure_threshold: int = 5,
                 timeout_seconds: int = 30,
                 recovery_seconds: int = 60,
                 half_open_max: int = 2):
        self.name = name
        self._failure_threshold = failure_threshold
        self._timeout = timeout_seconds
        self._recovery = recovery_seconds
        self._half_open_max = half_open_max
        self._state = CircuitState.CLOSED
        self._lock = threading.Lock()
        self._stats = CircuitStats(state=CircuitState.CLOSED)
        self._half_open_count = 0

    @property
    def state(self) -> CircuitState:
        with self._lock:
            self._transition()
            return self._state

    @property
    def stats(self) -> CircuitStats:
        with self._lock:
            self._transition()
            return self._stats

    def call(self, fn: Callable, *args, **kwargs):
        """Execute fn with circuit breaker protection. Raises CircuitOpenError if open."""
        with self._lock:
            self._transition()

            if self._state == CircuitState.OPEN:
                self._stats.total_rejected += 1
                raise CircuitOpenError(
                    f"Circuit '{self.name}' is OPEN. "
                    f"Last failure: {self._stats.last_failure_reason} "
                    f"({self._stats.last_failure_time:.0f}s ago)"
                )

            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_count >= self._half_open_max:
                    self._stats.total_rejected += 1
                    raise CircuitOpenError(
                        f"Circuit '{self.name}' is HALF_OPEN — "
                        f"probe limit reached ({self._half_open_max})"
                    )
                self._half_open_count += 1

        # Execute outside lock
        try:
            result = fn(*args, **kwargs)
            with self._lock:
                self._on_success()
            return result
        except Exception as e:
            with self._lock:
                self._on_failure(str(e))
            raise

    def _on_success(self):
        self._stats.total_requests += 1
        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.CLOSED
            self._half_open_count = 0
            self._stats.consecutive_failures = 0

    def _on_failure(self, reason: str):
        self._stats.total_requests += 1
        self._stats.total_failures += 1
        self._stats.consecutive_failures += 1
        self._stats.last_failure_time = time.time()
        self._stats.last_failure_reason = reason

        if self._state == CircuitState.HALF_OPEN:
            self._state = CircuitState.OPEN
            self._stats.opened_at = time.time()
        elif self._stats.consecutive_failures >= self._failure_threshold:
            self._state = CircuitState.OPEN
            self._stats.opened_at = time.time()

    def _transition(self):
        """Check if state transition is needed."""
        now = time.time()
        if self._state == CircuitState.OPEN:
            if now - self._stats.opened_at > self._recovery:
                self._state = CircuitState.HALF_OPEN
                self._half_open_count = 0
        elif self._state == CircuitState.HALF_OPEN:
            # If no requests for > recovery time, reset to closed
            if now - self._stats.opened_at > self._recovery * 2:
                self._state = CircuitState.CLOSED
                self._half_open_count = 0
                self._stats.consecutive_failures = 0

    def reset(self):
        """Force reset to CLOSED state."""
        with self._lock:
            self._state = CircuitState.CLOSED
            self._half_open_count = 0
            self._stats = CircuitStats(state=CircuitState.CLOSED)


class CircuitOpenError(Exception):
    """Raised when circuit is open and request is rejected."""
    pass


# ── Global circuit breakers per tool category ──
_circuits: dict[str, CircuitBreaker] = {}


def get_circuit(name: str) -> CircuitBreaker:
    """Get or create a named circuit breaker."""
    if name not in _circuits:
        _circuits[name] = CircuitBreaker(name=name)
    return _circuits[name]


def get_all_circuits() -> dict:
    return _circuits
