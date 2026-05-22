"""T3: Tiered least-privilege execution proxy.

exec_tier:
  "auto"    → execute directly (read-only diagnostics)
  "confirm" → execute as restricted user after T2 + user confirmation
  "veto"    → never execute (always blocked by T2)
"""
import subprocess
import os
from typing import Tuple

from agent.tools_manifest import (
    sandbox_allowlist, lookup_by_llm_name, exec_tier_for,
)

ALLOWED_READ_ONLY = sandbox_allowlist()

# Restricted user for confirm-tier commands — created during deployment
RESTRICTED_USER = "kylin-agent"


def _run(cmd_parts: list[str], timeout: int = 30,
         as_user: str | None = None) -> Tuple[int, str, str]:
    """Core subprocess runner with optional user switching."""
    if as_user:
        cmd_parts = ["sudo", "-n"] + cmd_parts

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
        return _run_file_tool(command, timeout)

    if base_cmd not in ALLOWED_READ_ONLY:
        return -1, "", f"Command '{base_cmd}' not in allowlist"

    # Auto tier only for actual execution — confirm-tier blocked here
    tier = exec_tier_for(base_cmd)
    if tier == "veto":
        return -1, "", f"Command '{base_cmd}' is vetoed — cannot execute"

    return _run(cmd_parts, timeout)


def _run_file_tool(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Handle file/shell operations directly via MCP implementations."""
    tokens = command.strip().split()
    tool = tokens[0]
    params = {}
    for t in tokens[1:]:
        if "=" in t:
            k, v = t.split("=", 1)
            params[k] = v
    from deps import _file_op, _exec_script
    if tool in ("create_file",):
        r = _file_op("create", params.get("path", ""), params.get("content", ""))
        return (0 if r.get("status") == "written" else 1, str(r), "")
    elif tool in ("append_file",):
        r = _file_op("append", params.get("path", ""), params.get("content", ""))
        return (0 if r.get("status") == "written" else 1, str(r), "")
    elif tool in ("execute_script",):
        r = _exec_script(params.get("path", ""))
        return (r.get("exit_code", 1), r.get("stdout", ""), r.get("stderr", ""))
    return -1, "", f"Unknown file tool: {tool}"


def execute_restricted(command: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Execute a confirm-tier command as the restricted user."""
    cmd_parts = command.strip().split()
    if not cmd_parts:
        return -1, "", "Empty command"

    base_cmd = cmd_parts[0]
    tier = exec_tier_for(base_cmd)
    if tier not in ("confirm", "auto"):
        return -1, "", f"Command '{base_cmd}' tier={tier} — cannot execute as restricted"

    return _run(cmd_parts, timeout, as_user=RESTRICTED_USER)


def can_execute_as_agent(command: str) -> bool:
    """Check if a command is in the execution allowlist (auto or confirm tier)."""
    base = command.strip().split()[0] if command.strip() else ""
    entry = lookup_by_llm_name(base)
    sandbox_cmd = entry["name"] if entry else base
    tier = exec_tier_for(sandbox_cmd)
    return tier in ("auto", "confirm")


def resolve_cmd(command_str: str) -> str:
    """Translate llm_name → sandbox_cmd and key=value params → CLI flags."""
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
