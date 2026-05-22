"""T2: Structural constraint engine — veto + alternative, not prompt-based.

Validates at two levels:
  1. Raw command string (regex patterns — legacy / direct shell commands)
  2. Structured tool call (tool_name + params — primary LLM output path)

Role-based confirmation thresholds
-----------------------------------
Each posture defines a base confirm score (e.g. balanced=5).
Each role adds an offset to that base, producing the effective threshold:
  effective = max(0, posture_base + role_offset)

Higher effective threshold → fewer confirm prompts (admin), lower → more (viewer).
Viewer offset of -999 clamps to 0, meaning every command requires confirmation.
"""
import os
import re
from typing import Dict, Optional
from dataclasses import dataclass

from agent.risk_posture import RiskPostureEngine

POSTURE_THRESHOLDS = RiskPostureEngine.POSTURE_THRESHOLDS

# Configurable via ROLE_CONFIRM_OFFSET_ADMIN / _OPERATOR / _VIEWER env vars
ROLE_CONFIRM_OFFSET = {
    "admin": int(os.getenv("ROLE_CONFIRM_OFFSET_ADMIN", "2")),
    "operator": int(os.getenv("ROLE_CONFIRM_OFFSET_OPERATOR", "0")),
    "viewer": int(os.getenv("ROLE_CONFIRM_OFFSET_VIEWER", "-999")),
}

# Viewer can only use these read-only tools (sandbox command names)
VIEWER_READONLY_TOOLS = {
    "ps", "df", "free", "ss", "journalctl", "systemctl", "lsof", "rpm",
}


@dataclass
class ValidationResult:
    allowed: bool
    requires_confirmation: bool = False
    reason: str = ""
    alternative: str = ""
    risk_score: int = 0


class ConstraintEngine:
    # ── Raw shell command patterns (legacy / direct shell input) ──
    PROHIBITED_RAW = [
        (r"rm\s+-rf\s+/", "Use 'rm -i' or move to /tmp instead of permanent deletion"),
        (r"mkfs\.", "Filesystem creation requires offline maintenance window"),
        (r"dd\s+if=", "Raw disk operations require physical console access"),
        (r">\s*/dev/sd[a-z]", "Writing to block devices requires manual approval"),
        (r"chmod\s+777\s+/", "Use more restrictive permissions (755 for dirs, 644 for files)"),
        (r"userdel\s+-r\s+root", "Root user cannot be deleted"),
        (r"passwd\s+root", "Root password changes require offline single-user mode"),
        (r":\(\)\s*\{\s*:\|:&\s*\};:", "Fork bomb detected"),
    ]

    CONFIRM_RAW = [
        (r"systemctl\s+(stop|disable|mask)", "Service control requires confirmation"),
        (r"kill\s+-9", "Use SIGTERM (-15) first; escalate to -9 only if unresponsive"),
        (r"chown\s+-R", "Recursive ownership change requires confirmation"),
        (r"rm\s+-rf\s+(?!\/)", "Recursive deletion requires confirmation"),
        (r"iptables\s+-F", "Flushing firewall rules may expose services"),
    ]

    # ── Structured tool constraints (primary path) ──
    DESTRUCTIVE_TOOLS = {
        "rm", "mkfs", "fdisk", "dd", "mkswap", "parted",
        "pvcreate", "vgremove", "lvremove", "mkfs.ext4", "mkfs.xfs",
    }

    DANGEROUS_PATHS = [
        "/dev/sd", "/dev/hd", "/dev/nvme", "/dev/xvd",
        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/sudoers.d",
        "/boot", "/boot/efi", "/sys/kernel", "/proc/sys",
        "/root/.ssh", "/home/",
    ]

    DANGEROUS_PARAM_VALUES: Dict[str, list] = {
        "action": ["stop", "disable", "mask", "delete", "remove", "restart"],
        "mode": ["777", "666", "7777"],
        "permissions": ["777", "666", "7777"],
        "target": ["iptables", "firewalld", "nginx", "httpd", "sshd"],
    }

    DANGEROUS_FLAGS = {"-rf", "-Rf", "--force", "-9", "-KILL", "-SIGKILL"}

    # File operation blocked path prefixes
    BLOCKED_PATH_PREFIXES = ("/etc", "/boot", "/sys", "/proc", "/root")

    def _check_file_path(self, path: str) -> Optional[ValidationResult]:
        """Validate a file path for create/append operations."""
        import os as _os
        if not path:
            return ValidationResult(allowed=False, reason="File path is required", risk_score=10)
        abs_path = _os.path.abspath(_os.path.expanduser(path))
        for prefix in self.BLOCKED_PATH_PREFIXES:
            if abs_path.startswith(prefix + "/") or abs_path == prefix:
                return ValidationResult(
                    allowed=False,
                    reason=f"Path '{abs_path}' is blocked (prefix: {prefix})",
                    alternative=f"Use /tmp or /var/log instead of {prefix}",
                    risk_score=10,
                )
        return None

    def _check_script_path(self, path: str) -> Optional[ValidationResult]:
        """Validate script path + shebang for execute_script."""
        import os as _os
        if not path:
            return ValidationResult(allowed=False, reason="Script path is required", risk_score=10)
        abs_path = _os.path.abspath(_os.path.expanduser(path))
        if not abs_path.startswith("/tmp/kylin-agent"):
            return ValidationResult(
                allowed=False,
                reason=f"Script path '{abs_path}' not under /tmp/kylin-agent",
                alternative="Copy the script to /tmp/kylin-agent/ first",
                risk_score=10,
            )
        if _os.path.isfile(abs_path):
            try:
                with open(abs_path) as f:
                    first = f.readline().strip()
                if first.startswith("#!") and any(
                    p in first for p in ("python", "perl", "ruby")
                ):
                    return ValidationResult(
                        allowed=False,
                        reason=f"Shebang rejected: {first}",
                        alternative="Use bash or sh for scripts under kylin-agent",
                        risk_score=10,
                    )
            except OSError:
                pass
        return None

    def validate(self, command: str, posture: str = "balanced",
                 params: Optional[dict] = None, role: str = "operator",
                 intent_profile: dict = None) -> ValidationResult:
        """Validate a command: structured if params provided, raw regex otherwise."""
        if params is not None:
            return self._validate_tool_call(command, params, posture, role, intent_profile)
        return self._validate_raw(command, posture)

    def _validate_raw(self, command: str, posture: str = "balanced") -> ValidationResult:
        cmd_clean = command.strip()

        for pattern, alternative in self.PROHIBITED_RAW:
            if re.search(pattern, cmd_clean):
                return ValidationResult(
                    allowed=False,
                    reason=f"Command matches prohibited pattern: {pattern[:40]}...",
                    alternative=alternative,
                    risk_score=10,
                )

        for pattern, reason in self.CONFIRM_RAW:
            if re.search(pattern, cmd_clean):
                threshold = POSTURE_THRESHOLDS
                risk = self._estimate_risk(cmd_clean)
                needs_confirm = risk >= threshold.get(posture, 5)
                return ValidationResult(
                    allowed=True,
                    requires_confirmation=needs_confirm,
                    reason=reason,
                    risk_score=risk,
                )

        return ValidationResult(allowed=True, risk_score=self._estimate_risk(cmd_clean))

    def _validate_tool_call(self, tool_name: str, params: dict,
                            posture: str = "balanced", role: str = "operator",
                            intent_profile: dict = None) -> ValidationResult:
        # 0. Intent profile risk boost: escalate threshold on suspicious signals
        intent_boost = 0
        if intent_profile:
            risk_hint = intent_profile.get("risk_hint", "normal")
            urgency = intent_profile.get("urgency", "low")
            prior = intent_profile.get("prior_behavior", "")
            if risk_hint != "normal":
                intent_boost = 2  # any non-normal risk_hint → stricter
            if "越权" in risk_hint or "越权" in prior:
                intent_boost = 4  # role escalation attempt → much stricter
            if urgency in ("high", "critical"):
                intent_boost = max(intent_boost, 1)  # urgency → slightly stricter
            if "被拒" in prior or "重试" in prior:
                intent_boost = max(intent_boost, 3)  # retry after rejection → stricter

        # 0. File/create operations: path whitelist check
        if params and "path" in params:
            path = str(params.get("path", ""))
            if path:
                result = self._check_file_path(path)
                if result and not result.allowed:
                    return result
                # Confirm-tier for system paths
                abs_path = __import__("os").path.abspath(__import__("os").path.expanduser(path))
                if abs_path.startswith("/var") or abs_path.startswith("/usr"):
                    risk = 7
                    needs_confirm = risk >= self._effective_threshold(posture, role, intent_boost)
                    return ValidationResult(
                        allowed=True,
                        requires_confirmation=needs_confirm,
                        reason=f"Writing to system path {abs_path} requires confirmation",
                        risk_score=risk,
                    )
                # Content inspection: dangerous content → confirm
                content = str(params.get("content", ""))
                if content:
                    from agent.tools_manifest import WRITE_INDICATORS
                    content_lower = content.lower()
                    for indicator in WRITE_INDICATORS:
                        if indicator.lower() in content_lower:
                            return ValidationResult(
                                allowed=True,
                                requires_confirmation=True,
                                reason=f"File content contains dangerous pattern: '{indicator}'",
                                risk_score=7,
                            )

        # 0a. Script execution: path + shebang check
        if params and tool_name == "bash" and "path" in params:
            path = str(params.get("path", ""))
            if path:
                result = self._check_script_path(path)
                if result:
                    return result

        # 1. Viewer role can only use read-only tools
        if role == "viewer" and tool_name not in VIEWER_READONLY_TOOLS:
            return ValidationResult(
                allowed=False,
                reason=f"Viewer role cannot use '{tool_name}' (read-only tools only)",
                alternative="Request an operator or admin to perform this action",
                risk_score=10,
            )

        # 1. Tool name itself prohibited?
        if tool_name in self.DESTRUCTIVE_TOOLS:
            return ValidationResult(
                allowed=False,
                reason=f"Tool '{tool_name}' is destructive (blocked at T2)",
                alternative="Use read-only diagnostic tools instead",
                risk_score=10,
            )

        # 2. Param values contain dangerous paths?
        for key, value in params.items():
            value_str = str(value)
            for path in self.DANGEROUS_PATHS:
                # Match only as a path prefix (path is "/boot", "/dev/sd", etc.)
                if value_str.startswith(path):
                    return ValidationResult(
                        allowed=False,
                        reason=f"Param '{key}' contains protected path '{path}'",
                        alternative=f"Access to {path} requires manual approval",
                        risk_score=10,
                    )

        # 3. Dangerous param key-value combinations → confirm
        for key, value in params.items():
            value_str = str(value).lower()
            if key in self.DANGEROUS_PARAM_VALUES:
                if value_str in self.DANGEROUS_PARAM_VALUES[key]:
                    risk = 7
                    needs_confirm = risk >= self._effective_threshold(posture, role, intent_boost)
                    return ValidationResult(
                        allowed=True,
                        requires_confirmation=needs_confirm,
                        reason=f"Param {key}={value} requires confirmation",
                        risk_score=risk,
                    )

        # 4. Dangerous flag keys → confirm
        for key in params:
            if key in self.DANGEROUS_FLAGS:
                risk = 8
                needs_confirm = risk >= self._effective_threshold(posture, role, intent_boost)
                return ValidationResult(
                    allowed=True,
                    requires_confirmation=needs_confirm,
                    reason=f"Flag '{key}' requires confirmation",
                    risk_score=risk,
                )

        return ValidationResult(allowed=True, risk_score=1)

    def _effective_threshold(self, posture: str, role: str,
                              intent_boost: int = 0) -> int:
        base = POSTURE_THRESHOLDS.get(posture, 5)
        offset = ROLE_CONFIRM_OFFSET.get(role, 0)
        return max(0, base + offset - intent_boost)

    def _estimate_risk(self, command: str) -> int:
        score = 1
        if any(kw in command for kw in ["stop", "kill", "delete", "remove", "rm "]):
            score += 2
        if any(kw in command for kw in ["disable", "mask", "flush"]):
            score += 2
        if any(kw in command for kw in ["-rf", "-R", "-9"]):
            score += 2
        if ">" in command:
            score += 2
        return min(10, score)
