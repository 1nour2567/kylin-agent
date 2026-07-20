"""Task-level capability tokens for state-changing tool executions.

This is a deliberately small Task-Level CapBAC implementation.  It borrows the
idea of contextual caveats (a token is bound to an exact task context), but it
is not a Macaroons implementation: there is no caveat delegation or chained
HMAC construction.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import asdict, dataclass, replace
from typing import Any, Callable, Optional

from agent.tools_manifest import MANIFEST, lookup_by_llm_name, lookup_by_mcp_name


CAPABILITY_VERSION = "tl-capbac-v1"
MAX_TTL_SECONDS = 300


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def stable_json(value: Any) -> str:
    """Return the sole serialization form used for scopes and parameter hashes."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _manifest_entry(tool_name: str) -> dict:
    entry = lookup_by_llm_name(tool_name) or lookup_by_mcp_name(tool_name)
    if entry:
        return entry
    matches = [item for item in MANIFEST if item.get("name") == tool_name]
    if len(matches) == 1:
        return matches[0]
    raise ValueError(f"Unknown or ambiguous tool: {tool_name}")


def canonical_tool_name(tool_name: str) -> str:
    entry = _manifest_entry(str(tool_name or "").strip())
    canonical = entry.get("llm_name") or entry.get("mcp_name")
    if not canonical:
        raise ValueError(f"Tool is not executable: {tool_name}")
    return canonical


def _normalize_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value!r}")


_OPTIONAL_DEFAULTS: dict[str, dict[str, Any]] = {
    "ps_processes": {"limit": 10},
    "journalctl_logs": {"unit": "", "lines": 50},
    "rpm_verify": {"package": ""},
    "journalctl_clean": {"days": "7"},
    "create_file": {"content": ""},
    "append_file": {"content": ""},
    "kill_process": {"signal": 15},
}


def canonicalize_params(tool_name: str, params: Optional[dict]) -> tuple[str, dict]:
    """Normalize a tool call according to its manifest-declared parameter types."""
    canonical = canonical_tool_name(tool_name)
    entry = _manifest_entry(canonical)
    raw = dict(params or {})

    if "path" not in raw:
        for alias in ("file", "filename"):
            if alias in raw:
                raw["path"] = raw.pop(alias)
                break

    schema = dict(entry.get("params") or {})
    if canonical == "kill_process":
        schema.setdefault("signal", "int")
    unknown = set(raw) - set(schema)
    if unknown:
        raise ValueError(f"Unexpected parameters for {canonical}: {sorted(unknown)}")

    defaults = _OPTIONAL_DEFAULTS.get(canonical, {})
    normalized: dict[str, Any] = {}
    for key, declared_type in schema.items():
        if key in raw:
            value = raw[key]
        elif key in defaults:
            value = defaults[key]
        else:
            raise ValueError(f"Missing required parameter '{key}' for {canonical}")

        kind = str(declared_type).strip().lower()
        if key == "path":
            text = str(value).strip()
            if not text:
                raise ValueError(f"Parameter '{key}' cannot be empty for {canonical}")
            normalized[key] = os.path.realpath(os.path.abspath(os.path.expanduser(text)))
        elif key in {"pid", "signal", "limit", "lines"} or kind in {"int", "integer"}:
            number = int(value)
            if key in {"pid", "limit", "lines"} and number < 1:
                raise ValueError(f"Parameter '{key}' must be positive")
            if key == "signal":
                number = abs(number)
                if number not in {15}:
                    raise ValueError("Only SIGTERM (15) is allowed")
            normalized[key] = number
        elif kind in {"bool", "boolean"}:
            normalized[key] = _normalize_bool(value)
        elif kind in {"float", "number"}:
            normalized[key] = float(value)
        elif kind in {"list", "array"}:
            if not isinstance(value, list):
                raise ValueError(f"Parameter '{key}' must be a list")
            normalized[key] = value
        elif kind in {"dict", "object"}:
            if not isinstance(value, dict):
                raise ValueError(f"Parameter '{key}' must be an object")
            normalized[key] = value
        else:
            normalized[key] = str(value).strip() if key != "content" else str(value)

    return canonical, normalized


def normalized_params_hash(tool_name: str, params: Optional[dict]) -> tuple[str, dict, str]:
    canonical, normalized = canonicalize_params(tool_name, params)
    digest = hashlib.sha256(stable_json(normalized).encode("utf-8")).hexdigest()
    return canonical, normalized, digest


def _resource_for(tool_name: str, params: dict) -> str:
    for key in ("path", "service", "pid", "unit", "package"):
        value = params.get(key)
        if value not in (None, ""):
            return f"{key}:{value}"
    return f"tool:{tool_name}"


@dataclass(frozen=True)
class CapabilityScope:
    version: str
    subject: str
    role: str
    tool_name: str
    action: str
    resource: str
    normalized_params_hash: str
    trace_id: str
    operation_id: str
    event_id: str
    issued_at: float
    expires_at: float
    nonce: str
    single_use: bool = True

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict) -> "CapabilityScope":
        fields = cls.__dataclass_fields__
        missing = set(fields) - set(value)
        if missing:
            raise ValueError(f"Capability scope missing fields: {sorted(missing)}")
        return cls(**{key: value[key] for key in fields})

    def binding_dict(self) -> dict:
        """Fields that must match the exact task at execution time."""
        return {
            "version": self.version,
            "subject": self.subject,
            "role": self.role,
            "tool_name": self.tool_name,
            "action": self.action,
            "resource": self.resource,
            "normalized_params_hash": self.normalized_params_hash,
            "trace_id": self.trace_id,
            "operation_id": self.operation_id,
            "event_id": self.event_id,
            "single_use": self.single_use,
        }

    def digest(self) -> str:
        return hashlib.sha256(stable_json(self.binding_dict()).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CapabilityVerificationResult:
    valid: bool
    reason: str
    jti: str = ""
    scope_digest: str = ""
    payload: Optional[CapabilityScope] = None

    def public_dict(self) -> dict:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "jti": hashlib.sha256(self.jti.encode("utf-8")).hexdigest()[:16] if self.jti else "",
            "scope_digest": self.scope_digest[:16],
        }


class CapabilityReplayStore:
    """Thread-safe, JSON-persisted single-use nonce store."""

    def __init__(self, path: str, clock: Callable[[], float] | None = None):
        self.path = path
        self.clock = clock or time.time
        self._lock = threading.RLock()
        self._consumed: dict[str, float] = {}
        self._load()
        self.cleanup_expired_nonces()

    def consume(self, nonce: str, expires_at: float) -> bool:
        with self._lock:
            self._cleanup_locked()
            if nonce in self._consumed:
                return False
            self._consumed[nonce] = float(expires_at)
            self._save_locked()
            return True

    def cleanup_expired_nonces(self) -> int:
        with self._lock:
            removed = self._cleanup_locked()
            if removed:
                self._save_locked()
            return removed

    def _cleanup_locked(self) -> int:
        now = self.clock()
        expired = [nonce for nonce, expiry in self._consumed.items() if expiry <= now]
        for nonce in expired:
            del self._consumed[nonce]
        return len(expired)

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                value = json.load(handle)
            if isinstance(value, dict):
                self._consumed = {str(k): float(v) for k, v in value.items()}
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._consumed = {}

    def _save_locked(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        temp_path = self.path + ".tmp"
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(self._consumed, handle, sort_keys=True, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, self.path)


class CapabilityTokenService:
    """Issue, verify, and atomically consume HMAC-SHA256 task capabilities."""

    def __init__(
        self,
        replay_store: CapabilityReplayStore,
        secret: str | bytes,
        ttl_seconds: int = 60,
        clock: Callable[[], float] | None = None,
    ):
        if not secret:
            raise ValueError("CAPABILITY_TOKEN_SECRET is required")
        self.replay_store = replay_store
        self.secret = secret.encode("utf-8") if isinstance(secret, str) else secret
        self.ttl_seconds = max(1, min(int(ttl_seconds), MAX_TTL_SECONDS))
        self.clock = clock or time.time

    def build_scope(
        self,
        tool_name: str,
        params: Optional[dict],
        actor_context: dict,
        trace_id: str,
        operation_id: str,
        event_id: str,
        single_use: bool = True,
    ) -> CapabilityScope:
        canonical, normalized, params_digest = normalized_params_hash(tool_name, params)
        subject = str(actor_context.get("user_id") or actor_context.get("subject") or "")
        role = str(actor_context.get("role") or "")
        if not all((subject, role, trace_id, operation_id, event_id)):
            raise ValueError("Capability scope requires user, role, trace_id, operation_id, and event_id")
        now = self.clock()
        scope = CapabilityScope(
            version=CAPABILITY_VERSION,
            subject=subject,
            role=role,
            tool_name=canonical,
            action=canonical,
            resource=_resource_for(canonical, normalized),
            normalized_params_hash=params_digest,
            trace_id=str(trace_id),
            operation_id=str(operation_id),
            event_id=str(event_id),
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            nonce=secrets.token_urlsafe(18),
            single_use=bool(single_use),
        )
        self._audit("capability_scope_created", scope, "scope_constructed")
        return scope

    def issue(self, scope: CapabilityScope) -> str:
        now = self.clock()
        issued = replace(
            scope,
            issued_at=now,
            expires_at=now + self.ttl_seconds,
            nonce=secrets.token_urlsafe(18),
        )
        payload_bytes = stable_json(issued.to_dict()).encode("utf-8")
        signature = hmac.new(self.secret, payload_bytes, hashlib.sha256).digest()
        token = f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"
        self._audit("capability_issued", issued, "issued")
        return token

    def verify(
        self, token: str, expected_scope: CapabilityScope
    ) -> CapabilityVerificationResult:
        try:
            payload_part, signature_part = token.split(".", 1)
            payload_bytes = _b64url_decode(payload_part)
            actual_signature = _b64url_decode(signature_part)
        except Exception:
            result = CapabilityVerificationResult(False, "malformed_token")
            self._audit_result("capability_rejected", expected_scope, result)
            return result

        expected_signature = hmac.new(self.secret, payload_bytes, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_signature, expected_signature):
            result = CapabilityVerificationResult(False, "invalid_signature")
            self._audit_result("capability_rejected", expected_scope, result)
            return result

        try:
            payload = CapabilityScope.from_dict(json.loads(payload_bytes.decode("utf-8")))
        except Exception:
            result = CapabilityVerificationResult(False, "invalid_payload")
            self._audit_result("capability_rejected", expected_scope, result)
            return result

        if payload.version != CAPABILITY_VERSION:
            result = CapabilityVerificationResult(False, "unsupported_version", payload.nonce, payload.digest())
        elif payload.expires_at <= self.clock():
            result = CapabilityVerificationResult(False, "expired", payload.nonce, payload.digest(), payload)
        elif not hmac.compare_digest(
            stable_json(payload.binding_dict()).encode("utf-8"),
            stable_json(expected_scope.binding_dict()).encode("utf-8"),
        ):
            result = CapabilityVerificationResult(False, "scope_mismatch", payload.nonce, payload.digest(), payload)
        else:
            result = CapabilityVerificationResult(True, "verified", payload.nonce, payload.digest(), payload)

        event = "capability_verified" if result.valid else (
            "capability_expired" if result.reason == "expired" else "capability_rejected"
        )
        self._audit_result(event, payload, result)
        return result

    def verify_and_consume(
        self, token: str, expected_scope: CapabilityScope
    ) -> CapabilityVerificationResult:
        result = self.verify(token, expected_scope)
        if not result.valid or result.payload is None:
            return result
        if result.payload.single_use and not self.replay_store.consume(
            result.payload.nonce, result.payload.expires_at
        ):
            replay = CapabilityVerificationResult(
                False, "replay_blocked", result.payload.nonce, result.payload.digest(), result.payload
            )
            self._audit_result("capability_replay_blocked", result.payload, replay)
            return replay
        consumed = CapabilityVerificationResult(
            True, "consumed", result.payload.nonce, result.payload.digest(), result.payload
        )
        self._audit_result("capability_consumed", result.payload, consumed)
        return consumed

    def cleanup_expired_nonces(self) -> int:
        return self.replay_store.cleanup_expired_nonces()

    @staticmethod
    def scopes_match(left: CapabilityScope, right: CapabilityScope) -> bool:
        return hmac.compare_digest(
            stable_json(left.binding_dict()).encode("utf-8"),
            stable_json(right.binding_dict()).encode("utf-8"),
        )

    def _audit(self, event_type: str, scope: CapabilityScope, reason: str) -> None:
        try:
            from audit.trail import AuditTrail
            AuditTrail(scope.subject, role=scope.role).security_event(event_type, {
                "jti_hash": hashlib.sha256(scope.nonce.encode("utf-8")).hexdigest()[:16],
                "scope_digest": scope.digest(),
                "tool": scope.tool_name,
                "resource": scope.resource,
                "trace_id": scope.trace_id,
                "event_id": scope.event_id,
                "reason": reason,
            })
        except Exception:
            pass

    def _audit_result(
        self,
        event_type: str,
        scope: CapabilityScope,
        result: CapabilityVerificationResult,
    ) -> None:
        self._audit(event_type, scope, result.reason)

