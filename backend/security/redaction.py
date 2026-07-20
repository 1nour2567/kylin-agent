"""Sensitive value redaction helpers for logs, audit events, and UI pushes."""
from __future__ import annotations

import re
from typing import Any


_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|token|access[_-]?token|refresh[_-]?token|secret|password)"
    r"(\s*[:=]\s*)(['\"]?)([^'\"\s,;]{6,})"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{10,})")
_COMMON_KEY_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{8,}|kylin_[a-fA-F0-9]{16,})\b")


def _mask(value: str, keep: int = 4) -> str:
    if len(value) <= keep:
        return "***"
    return f"{value[:keep]}...REDACTED"


def redact_text(text: Any) -> str:
    """Return text with likely credentials masked."""
    if text is None:
        return ""
    s = str(text)

    def repl_assignment(match: re.Match) -> str:
        key, sep, quote, value = match.groups()
        return f"{key}{sep}{quote}{_mask(value)}"

    s = _ASSIGNMENT_RE.sub(repl_assignment, s)
    s = _BEARER_RE.sub(lambda m: "Bearer " + _mask(m.group(1)), s)
    s = _COMMON_KEY_RE.sub(lambda m: _mask(m.group(1)), s)
    return s


def redact_obj(value: Any) -> Any:
    """Recursively redact strings inside JSON-like values."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_s = str(key)
            if re.search(r"(?i)(api[_-]?key|token|secret|password)", key_s):
                redacted[key] = _mask(str(item))
            else:
                redacted[key] = redact_obj(item)
        return redacted
    if isinstance(value, list):
        return [redact_obj(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_obj(item) for item in value)
    return value
