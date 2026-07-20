"""T3: Tiered least-privilege execution proxy.

exec_tier:
  "auto"    → execute directly (read-only diagnostics)
  "confirm" → execute as restricted user after T2 + user confirmation
  "veto"    → never execute (always blocked by T2)

Rollback: all file-modifying operations are snapshotted before execution.
"""
import subprocess
import os
import getpass
from typing import Tuple, Optional

from config import settings
from agent.tools_manifest import (
    sandbox_allowlist, lookup_by_llm_name, exec_tier_for,
)
from security.rollback import RollbackManager

ALLOWED_READ_ONLY = sandbox_allowlist()

# Restricted user for confirm-tier commands — created during deployment
RESTRICTED_USER = settings.restricted_user
PRIVILEGED_CONFIRM_ALLOWLIST = {
    ("systemctl", "restart"),
    ("journalctl", "--vacuum-time"),
    ("kill", "-15"),
    ("truncate", "-s"),
}

_rollback = RollbackManager()


def snapshot_before_write(file_path: str, operation: str = "write") -> Optional[str]:
    """Snapshot a file before modification. Returns entry_id for restore, or None."""
    if not file_path:
        return None
    entry = _rollback.snapshot(file_path, operation)
    return entry.entry_id if entry else None


def get_rollback() -> RollbackManager:
    """Expose the rollback manager for API endpoints."""
    return _rollback


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""


def _is_privileged_confirm_allowed(cmd_parts: list[str]) -> bool:
    if not settings.allow_privileged_confirm or len(cmd_parts) < 2:
        return False
    return (cmd_parts[0], cmd_parts[1]) in PRIVILEGED_CONFIRM_ALLOWLIST


def _run(cmd_parts: list[str], timeout: int = 30,
         as_user: str | None = None,
         use_sudo: bool = False) -> Tuple[int, str, str]:
    """Core subprocess runner with optional user switching."""
    cmd_parts = list(cmd_parts)
    if as_user and os.name != "nt" and _current_user() != as_user:
        cmd_parts = ["sudo", "-n", "-u", as_user, "--"] + cmd_parts
    elif use_sudo and os.name != "nt":
        cmd_parts = ["sudo", "-n", "--"] + cmd_parts

    env = os.environ.copy()
    extra = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    current = set(env.get("PATH", "").split(":"))
    current.update(extra)
    env["PATH"] = ":".join(current)

    try:
        proc = subprocess.run(
            cmd_parts, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        return proc.returncode, proc.stdout[:5000], proc.stderr[:5000]
    except subprocess.TimeoutExpired:
        return -1, "", f"Command timed out after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd_parts[0]}"
    except Exception as e:
        return -1, "", str(e)


def execute(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Auto-tier execution — only for read-only / auto-tier commands."""
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return -1, "", "Empty command"

    base_cmd = cmd_parts[0]

    # File operations are handled by MCP implementation, not shell
    if base_cmd in ("create_file", "append_file", "execute_script"):
        return -1, "", "State-changing file tools must use ExecutionGateway with a capability token"

    if base_cmd not in ALLOWED_READ_ONLY:
        return -1, "", f"Command '{base_cmd}' not in allowlist"

    # Auto tier only for actual execution — confirm-tier blocked here
    tier = exec_tier_for(base_cmd)
    if tier == "veto":
        return -1, "", f"Command '{base_cmd}' is vetoed — cannot execute"

    return _run(cmd_parts, timeout)


def _run_file_tool(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Compatibility shim that is intentionally fail-closed.

    File/script implementations live in agent.tool_runtime and can only be
    reached through ExecutionGateway after capability verification.
    """
    return -1, "", "Direct file-tool execution is disabled; use ExecutionGateway"


def execute_restricted(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Execute a confirm-tier command as the restricted user."""
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return -1, "", "Empty command"

    base_cmd = cmd_parts[0]
    tier = exec_tier_for(base_cmd)
    if tier not in ("confirm", "auto"):
        return -1, "", f"Command '{base_cmd}' tier={tier} — cannot execute as restricted"

    if base_cmd in ("create_file", "append_file", "execute_script"):
        return -1, "", "State-changing file tools must use ExecutionGateway with a capability token"

    if _is_privileged_confirm_allowed(cmd_parts):
        return _run(cmd_parts, timeout, use_sudo=True)

    if _running_as_root():
        return _run(cmd_parts, timeout, as_user=RESTRICTED_USER)

    return _run(cmd_parts, timeout)


def can_execute_as_agent(command: str) -> bool:
    """Check if a command is in the execution allowlist (auto or confirm tier)."""
    base = command.strip().split()[0] if command.strip() else ""
    entry = lookup_by_llm_name(base)
    if entry:
        return entry.get("exec_tier") in ("auto", "confirm")
    elif base in ALLOWED_READ_ONLY:
        from agent.tools_manifest import MANIFEST
        matches = [item for item in MANIFEST if item.get("name") == base]
        # Bare binary names are accepted only when they are unambiguous.
        return len(matches) == 1 and matches[0].get("exec_tier") in ("auto", "confirm")
    else:
        return False


def resolve_cmd(tool_name: str, params: dict | None = None) -> str:
    """Build sandbox command from tool name + structured params dict (#05).

    Accepts both legacy string format (backward compat) and new (tool_name, params) tuple.
    """
    # Backward compat: if called with old-style string
    if params is None and isinstance(tool_name, str) and "=" in tool_name:
        return _resolve_cmd_legacy(tool_name)

    params = params or {}
    entry = lookup_by_llm_name(tool_name)
    if not entry:
        return tool_name

    parts = [entry["name"]]
    parts.extend(entry.get("default_args", []))

    param_flags = entry.get("param_flags", {})
    for key, value in params.items():
        flag = param_flags.get(key)
        if flag:
            parts.append(flag)
        parts.append(str(value))

    return " ".join(parts)


def _resolve_cmd_legacy(command_str: str) -> str:
    """Old-style: parse 'tool_name key=value' string. Kept for backward compat."""
    tokens = command_str.strip().split()
    if not tokens:
        return command_str

    entry = lookup_by_llm_name(tokens[0])
    if not entry:
        return command_str

    result = [entry["name"]]
    result.extend(entry.get("default_args", []))

    param_flags = entry.get("param_flags", {})
    for token in tokens[1:]:
        if "=" in token:
            key, value = token.split("=", 1)
            flag = param_flags.get(key)
            if flag is None:
                result.append(value)
            elif flag:
                result.append(flag)
                result.append(value)
        else:
            result.append(token)

    return " ".join(result)
