"""Deterministic defense for indirect prompt injection in external/tool output."""
from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Callable, Optional


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]")
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{12,}={0,2})(?![A-Za-z0-9+/_-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])((?:[0-9A-Fa-f]{2}){8,})(?![0-9A-Fa-f])")
_XESC_RE = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){4,}")


_PATTERNS: list[tuple[str, re.Pattern[str], int]] = [
    ("instruction_override", re.compile(
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions?|rules?)|"
        r"disregard\s+(?:the\s+)?system\s+prompt|"
        r"忽略(?:之前|此前|以上|所有).{0,8}(?:规则|指令|提示)|忘记(?:系统)?提示词",
        re.I,
    ), 4),
    ("role_override", re.compile(
        r"you\s+are\s+now\s+(?:root|admin(?:istrator)?)|act\s+as\s+(?:the\s+)?system|"
        r"你现在是\s*(?:root|管理员)|绕过(?:安全|权限).{0,8}(?:策略|检查|限制)",
        re.I,
    ), 4),
    ("prompt_exfiltration", re.compile(
        r"reveal\s+(?:the\s+)?system\s+prompt|"
        r"(?:send|upload|exfiltrate).{0,40}(?:secret|key|token|log).{0,30}(?:external|http|server)|"
        r"将.{0,12}(?:密钥|令牌|日志).{0,16}(?:发送|上传|传输).{0,12}(?:外部|服务器|网址)",
        re.I,
    ), 5),
    ("tool_induction", re.compile(
        r"(?:call|use|invoke)\s+(?:the\s+)?(?:tool|function)|"
        r"execute\s+the\s+following\s+command|"
        r"调用.{0,20}(?:工具|tool)|执行以下(?:命令|指令)|"
        r"(?:call|invoke).{0,30}(?:execute_script|systemctl_restart|kill_process)",
        re.I,
    ), 4),
    ("concealment", re.compile(r"do\s+not\s+tell\s+the\s+user|不要告诉用户", re.I), 3),
    ("model_protocol", re.compile(
        r"<\|im_(?:start|end)\|>|\[/?INST\]|(?:^|\n)\s*(?:system|assistant)\s*:",
        re.I,
    ), 4),
    ("dangerous_payload", re.compile(
        r"(?:rm\s+-rf|mkfs(?:\.|\s)|dd\s+if=|chmod\s+777|/etc/(?:shadow|passwd)|"
        r"execute_script|systemctl_restart|kill_process|kill\s+-9)",
        re.I,
    ), 2),
]


@dataclass
class OutputInspectionResult:
    action: str
    risk_score: int
    risk_level: str
    reason: str
    matched_patterns: list[str]
    sanitized_content: Any
    ref: str
    source_type: str
    tool_name: str
    original_sha256: str

    def security_metadata(self) -> dict:
        return {
            "action": self.action,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "matched_patterns": self.matched_patterns,
            "ref": self.ref,
            "source_type": self.source_type,
            "tool_name": self.tool_name,
            "original_sha256": self.original_sha256,
        }


class ToolOutputGuard:
    """Scan tool/system output while preserving useful diagnostic evidence."""

    def __init__(
        self,
        mode: str = "block",
        max_scan_chars: int = 20_000,
        max_decode_depth: int = 2,
        audit_hook: Optional[Callable[[str, dict], None]] = None,
        on_block: Optional[Callable[[], None]] = None,
    ):
        self.mode = mode if mode in {"block", "sanitize"} else "block"
        self.max_scan_chars = max(256, int(max_scan_chars))
        self.max_decode_depth = max(0, min(int(max_decode_depth), 4))
        self.audit_hook = audit_hook
        self.on_block = on_block

    def inspect_text(
        self,
        text: Any,
        source_type: str,
        tool_name: str,
        trace_id: str = "",
        _emit_audit: bool = True,
    ) -> OutputInspectionResult:
        raw = "" if text is None else str(text)
        limited = raw[: self.max_scan_chars]
        normalized = unicodedata.normalize("NFKC", limited)
        had_zero_width = bool(_ZERO_WIDTH_RE.search(normalized))
        normalized = _ZERO_WIDTH_RE.sub("", normalized)

        matches, score = self._match(normalized)
        decoded = self.scan_encoded_payloads(normalized)
        for decoded_text, encoding_name in decoded:
            decoded_matches, decoded_score = self._match(decoded_text)
            if decoded_matches:
                matches.extend(decoded_matches)
                matches.append(f"encoded_{encoding_name}")
                score += decoded_score + 2
        if had_zero_width and matches:
            matches.append("zero_width_obfuscation")
            score += 2

        matches = sorted(set(matches))
        score = min(10, score)
        digest = hashlib.sha256(raw.encode("utf-8", errors="replace")).hexdigest()
        ref = f"IPI-{digest[:12].upper()}"

        if score >= 6:
            action = "block" if self.mode == "block" else "sanitize"
            level = "high"
        elif score >= 3:
            action = "sanitize"
            level = "medium"
        else:
            action = "pass"
            level = "low"

        if action == "pass":
            sanitized = raw
            reason = "no_injection_signals"
        else:
            sanitized = self.sanitize_text(raw, ref)
            reason = "indirect_prompt_injection_signals"
            if action == "block":
                sanitized = f"[IPI_CONTENT_REMOVED ref={ref}]"

        result = OutputInspectionResult(
            action=action,
            risk_score=score,
            risk_level=level,
            reason=reason,
            matched_patterns=matches,
            sanitized_content=sanitized,
            ref=ref,
            source_type=source_type,
            tool_name=tool_name,
            original_sha256=digest,
        )
        if _emit_audit:
            self._record(result, trace_id)
        return result

    def inspect_object(
        self,
        obj: Any,
        source_type: str,
        tool_name: str,
        trace_id: str = "",
    ) -> OutputInspectionResult:
        all_matches: set[str] = set()
        max_score = 0
        strongest = "pass"
        refs: list[str] = []
        leaf_hashes: list[str] = []

        def walk(value: Any) -> Any:
            nonlocal max_score, strongest
            if isinstance(value, str):
                inspected = self.inspect_text(
                    value, source_type, tool_name, trace_id, _emit_audit=False
                )
                all_matches.update(inspected.matched_patterns)
                max_score = max(max_score, inspected.risk_score)
                leaf_hashes.append(inspected.original_sha256)
                if inspected.action == "block":
                    strongest = "block"
                elif inspected.action == "sanitize" and strongest == "pass":
                    strongest = "sanitize"
                if inspected.action != "pass":
                    refs.append(inspected.ref)
                return inspected.sanitized_content
            if isinstance(value, dict):
                return {key: walk(item) for key, item in value.items()}
            if isinstance(value, list):
                return [walk(item) for item in value]
            if isinstance(value, tuple):
                return tuple(walk(item) for item in value)
            return value

        sanitized = walk(obj)
        combined_hash = hashlib.sha256("".join(leaf_hashes).encode("ascii")).hexdigest()
        ref = refs[0] if refs else f"IPI-{combined_hash[:12].upper()}"
        level = "high" if strongest == "block" else ("medium" if strongest == "sanitize" else "low")
        result = OutputInspectionResult(
            action=strongest,
            risk_score=max_score,
            risk_level=level,
            reason="indirect_prompt_injection_signals" if strongest != "pass" else "no_injection_signals",
            matched_patterns=sorted(all_matches),
            sanitized_content=sanitized,
            ref=ref,
            source_type=source_type,
            tool_name=tool_name,
            original_sha256=combined_hash,
        )
        self._record(result, trace_id)
        return result

    def sanitize_text(self, text: str, ref: str) -> str:
        """Remove instruction-like suffixes while retaining preceding error evidence."""
        normalized = unicodedata.normalize("NFKC", text)
        normalized = _ZERO_WIDTH_RE.sub("", normalized)
        placeholder = f"[IPI_CONTENT_REMOVED ref={ref}]"
        output_lines: list[str] = []
        for line in normalized.splitlines() or [normalized]:
            starts = []
            for _, pattern, _ in _PATTERNS:
                match = pattern.search(line)
                if match:
                    starts.append(match.start())
            for pattern in (_BASE64_RE, _HEX_RE, _XESC_RE):
                for match in pattern.finditer(line):
                    decoded_matches = any(self._match(decoded)[0] for decoded, _ in self.scan_encoded_payloads(match.group(0)))
                    if decoded_matches:
                        starts.append(match.start())
            if not starts:
                output_lines.append(line)
                continue
            cut = min(starts)
            prefix = line[:cut].rstrip(" .;:,-")
            output_lines.append(f"{prefix + ' ' if prefix else ''}{placeholder}")
        sanitized = "\n".join(output_lines)
        return sanitized[: self.max_scan_chars]

    def scan_encoded_payloads(self, text: str) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        seen: set[str] = set()

        def visit(value: str, depth: int) -> None:
            if depth > self.max_decode_depth or len(value) > self.max_scan_chars:
                return
            candidates: list[tuple[str, str]] = []
            for match in _BASE64_RE.finditer(value):
                token = match.group(1)
                try:
                    padded = token + "=" * (-len(token) % 4)
                    decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8", errors="strict")
                    candidates.append((decoded, "base64"))
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    pass
            for match in _HEX_RE.finditer(value):
                try:
                    candidates.append((bytes.fromhex(match.group(1)).decode("utf-8"), "hex"))
                except (ValueError, UnicodeDecodeError):
                    pass
            for match in _XESC_RE.finditer(value):
                try:
                    token = match.group(0).replace("\\x", "")
                    candidates.append((bytes.fromhex(token).decode("utf-8"), "xescape"))
                except (ValueError, UnicodeDecodeError):
                    pass
            for decoded, encoding_name in candidates:
                if decoded in seen or not decoded.strip():
                    continue
                seen.add(decoded)
                found.append((decoded[: self.max_scan_chars], encoding_name))
                visit(decoded, depth + 1)

        visit(text, 1)
        return found

    @staticmethod
    def _match(text: str) -> tuple[list[str], int]:
        matches: list[str] = []
        score = 0
        for category, pattern, weight in _PATTERNS:
            if pattern.search(text):
                matches.append(category)
                score += weight
        # Dangerous strings alone are normal in logs; only score them when an
        # instruction/role/protocol signal is also present.
        if matches == ["dangerous_payload"]:
            return [], 0
        return matches, score

    def _record(self, result: OutputInspectionResult, trace_id: str) -> None:
        if result.action == "block" and self.on_block is not None:
            try:
                self.on_block()
            except Exception:
                pass
        event = {
            "pass": "tool_output_passed",
            "sanitize": "tool_output_sanitized",
            "block": "indirect_injection_blocked",
        }[result.action]
        if self.audit_hook is not None:
            try:
                self.audit_hook(event, {
                    **result.security_metadata(),
                    "trace_id": trace_id,
                })
            except Exception:
                pass
