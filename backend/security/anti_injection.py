"""T0: Anti-injection gateway — intercepts user input before LLM.

Pattern definitions live in patterns.py — single source of truth.
Sanitizer iterates PATTERNS and dispatches by category + action.
"""
import re
import base64
import unicodedata
from typing import Tuple

from security.patterns import PATTERNS, CATEGORY_LABELS, T0Pattern


def _decode_hex_escapes(text: str) -> str:
    """Decode \\xNN hex escape sequences to ASCII chars."""
    def _replace(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    return re.sub(r'\\x([0-9a-fA-F]{2})', _replace, text)

ZERO_WIDTH = re.compile(
    "[​‌‍‎‏⁠⁡⁢⁣⁤﻿­͏؜ᅟᅠ឴឵᠋-᠎ -‏ -  -⁤⁦-⁯￰-￸"
    "\U000e0001\U000e0020-\U000e007f\U000e0100-\U000e01ef]"
)


class Sanitizer:
    """Instance-based T0 sanitizer with internal reference counter."""

    def __init__(self):
        self.ref_counter = 0

    @staticmethod
    def normalize(text: str) -> str:
        """Unicode NFC normalization + strip zero-width/confusable characters."""
        text = unicodedata.normalize("NFKC", text)
        text = ZERO_WIDTH.sub("", text)
        return text

    def sanitize(self, user_input: str) -> Tuple[bool, str, str]:
        """Returns (is_blocked, sanitized_input, rejection_reference)."""
        user_input = self.normalize(user_input)

        # Overflow is special — not in PATTERNS (it's procedural)
        if len(user_input) > 8000:
            self.ref_counter += 1
            return True, "", f"REF-{self.ref_counter:05d}-OVERFLOW"

        for pattern in PATTERNS:
            if not re.search(pattern.regex, user_input):
                continue

            if pattern.action == "block":
                # Encoded patterns need decode + danger check
                if pattern.category == "encoded":
                    # Hex-encoded: check dangerous commands in decoded form
                    if _contains_hex_payload(user_input):
                        hex_decoded = _decode_hex_escapes(user_input)
                        if _contains_dangerous_command(hex_decoded):
                            self.ref_counter += 1
                            return True, "", f"REF-{self.ref_counter:05d}-ENCODED"
                    # Base64-encoded: decode and check
                    min_len = 40 if "20," in pattern.regex else 10
                    decoded = _try_decode_payload(user_input, min_len=min_len)
                    if not decoded or not _contains_dangerous_command(decoded):
                        continue
                self.ref_counter += 1
                cat_key = pattern.category.upper().replace("_", "")
                return True, "", f"REF-{self.ref_counter:05d}-{cat_key}"

            # action == "sanitize" or "warn" — future use
            if pattern.action == "sanitize":
                user_input = re.sub(pattern.regex, "", user_input)

        return False, user_input, ""


# Module-level singleton for backward compatibility
_default_sanitizer = Sanitizer()


def sanitize(user_input: str) -> Tuple[bool, str, str]:
    """Convenience wrapper using the default Sanitizer instance."""
    return _default_sanitizer.sanitize(user_input)


def _try_decode_payload(text: str, min_len: int = 40) -> str:
    m = re.search(rf"[\w+/=]{{{min_len},}}", text)
    if not m:
        return ""
    try:
        return base64.b64decode(m.group()).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _contains_dangerous_command(text: str) -> bool:
    dangerous = [r"rm\s+-rf\s+/", r"mkfs\.", r"dd\s+if=", r">\s*/dev/sd"]
    # Also check hex-decoded text for dangerous commands
    hex_decoded = _decode_hex_escapes(text)
    if hex_decoded != text:
        return any(re.search(p, hex_decoded, re.IGNORECASE) for p in dangerous) or \
               any(re.search(p, text, re.IGNORECASE) for p in dangerous)
    return any(re.search(p, text, re.IGNORECASE) for p in dangerous)


def _contains_hex_payload(text: str) -> bool:
    """Check if input contains hex-encoded shell commands piped to a shell."""
    # Match: printf/echo with hex escapes + pipe to sh/bash
    if re.search(r'(?:printf|echo|eval)\s+.*\\x[0-9a-fA-F]{2}.*\|', text):
        return True
    # Match standalone hex escape chains (4+ hex escapes = likely encoded)
    if len(re.findall(r'\\x[0-9a-fA-F]{2}', text)) >= 4:
        return True
    return False
