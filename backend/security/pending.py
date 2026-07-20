"""Canonical pending-confirmation records shared by every execution entry point."""
from __future__ import annotations

import subprocess
import time


def capture_process_comm(pid: object) -> str:
    if pid in (None, ""):
        return ""
    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def build_pending_entry(
    command_result: dict,
    user_id: str,
    role: str,
    posture: str,
    created_at: float | None = None,
    source: str = "chat",
) -> tuple[str, dict]:
    now = created_at if created_at is not None else time.time()
    params = dict(command_result.get("canonical_params") or {})
    tool_name = str(command_result.get("canonical_tool") or "")
    event_id = str(command_result.get("event_id") or "")
    scope = command_result.get("capability_scope")
    if not all((tool_name, event_id, command_result.get("operation_id"), command_result.get("trace_id"), scope)):
        raise ValueError("Pending write operation is missing canonical capability context")
    pid = params.get("pid", "")
    comm = capture_process_comm(pid) if tool_name == "kill_process" else ""
    return event_id, {
        "command": tool_name,
        "display_command": command_result.get("display_command", tool_name),
        "risk_label": command_result.get("risk_label", "?"),
        "user_id": user_id,
        "role": role,
        "created_at": now,
        "posture": posture,
        "source": source,
        "tool_name": tool_name,
        "params": params,
        "trace_id": command_result["trace_id"],
        "operation_id": command_result["operation_id"],
        "event_id": event_id,
        "capability_scope": scope,
        "file_path": str(params.get("path", "")),
        "operation": tool_name,
        "comm": comm,
        "target_fingerprint": {
            "path": params.get("path", ""),
            "pid": pid,
            "service": params.get("service", ""),
            "comm": comm,
            "snapshot_time": now,
        },
    }

