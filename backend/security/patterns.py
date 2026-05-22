"""T0 Pattern Registry — single source of truth for all injection patterns.

Each pattern has a category (for audit logging) and action (block / sanitize / warn).
Adding a new pattern only requires adding one line here — Sanitizer code stays unchanged.
"""
from dataclasses import dataclass


@dataclass
class T0Pattern:
    regex: str
    category: str   # role_switch | delimiter | encoded | overflow | unicode
    action: str     # block | sanitize | warn


PATTERNS: list[T0Pattern] = [
    # ── Delimiter injection ──
    T0Pattern(r"---+", "delimiter", "block"),
    T0Pattern(r"###+", "delimiter", "block"),
    T0Pattern(r"<\|", "delimiter", "block"),
    T0Pattern(r"\|>", "delimiter", "block"),
    T0Pattern(r"\[INST\]", "delimiter", "block"),
    T0Pattern(r"\[/INST\]", "delimiter", "block"),
    T0Pattern(r"<\|im_start\|>", "delimiter", "block"),
    T0Pattern(r"<\|im_end\|>", "delimiter", "block"),
    T0Pattern(r"<system>", "delimiter", "block"),
    T0Pattern(r"</system>", "delimiter", "block"),

    # ── Role switch / prompt injection ──
    T0Pattern(
        r"(?i)(?:ignore|disregard|disobey|forget|pretend|act\s+as)\s+(all\s+)?"
        r"(previous|prior|above)\s+(instructions?|prompts?|constraints?)",
        "role_switch", "block",
    ),
    T0Pattern(r"(?i)you\s+are\s+(now|no\s+longer)\s+a", "role_switch", "block"),
    T0Pattern(r"(?i)forget\s+(everything|all)\s+(you|i)\s+(said|told)", "role_switch", "block"),
    T0Pattern(r"(?i)pretend\s+(you\s+are|to\s+be)", "role_switch", "block"),
    T0Pattern(r"(?i)act\s+as\s+(if\s+)?(you\s+are|a)", "role_switch", "block"),
    T0Pattern(r"(?i)new\s+instructions?", "role_switch", "block"),
    T0Pattern(r"(?i)disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
              "role_switch", "block"),
    T0Pattern(r"(?i)disobey\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?)",
              "role_switch", "block"),

    # ── Encoded payload ──
    T0Pattern(
        r"(?i)(?:echo|print|eval|exec|base64\s+(?:-d|--decode))\s+[\w+/=]{20,}",
        "encoded", "block",
    ),

    # ── Short encoded payload (10+ chars, catches brief base64) ──
    T0Pattern(
        r"(?i)(?:echo|print|eval|exec)\s+[\w+/=]{10,}",
        "encoded", "block",
    ),

    # ── Hex-encoded payload (printf \\x72\\x6d... | sh) ──
    T0Pattern(
        r"(?i)(?:printf|echo|eval)\s+.*\\x[0-9a-fA-F]{2}.*\|",
        "encoded", "block",
    ),
    T0Pattern(
        r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}",
        "encoded", "block",
    ),
]

# Category descriptions for audit logging
CATEGORY_LABELS = {
    "delimiter": "分隔符注入",
    "role_switch": "角色越狱",
    "encoded": "编码载荷",
    "overflow": "输入过长",
    "unicode": "Unicode混淆",
}
