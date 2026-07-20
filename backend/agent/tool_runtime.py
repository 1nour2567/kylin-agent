"""Concrete tool implementations used only behind the execution gateway."""
from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any

from config import settings
from security.sandbox import _current_user, _run, _running_as_root, snapshot_before_write


@dataclass
class RuntimeResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    command_display: str = ""


class ToolRuntime:
    """Resolve structured tools to fixed argv or safe in-process file operations."""

    FILE_TOOLS = {"create_file", "append_file", "execute_script"}

    def execute(self, tool_name: str, params: dict, timeout: int = 30) -> RuntimeResult:
        if tool_name == "create_file":
            return self._file_op("create", params)
        if tool_name == "append_file":
            return self._file_op("append", params)
        if tool_name == "execute_script":
            return self._exec_script(params, timeout)

        argv, restricted = self._build_argv(tool_name, params)
        display = " ".join(str(part) for part in argv)
        if restricted and _running_as_root():
            code, stdout, stderr = _run(argv, timeout, as_user=settings.restricted_user)
        else:
            code, stdout, stderr = _run(argv, timeout)

        if tool_name == "ps_processes" and code == 0:
            limit = int(params.get("limit", 10))
            stdout = "\n".join(stdout.splitlines()[:limit])
        return RuntimeResult(code, stdout, stderr, display)

    @staticmethod
    def _build_argv(tool_name: str, params: dict) -> tuple[list[str], bool]:
        readonly: dict[str, list[Any]] = {
            "ps_processes": ["ps", "aux", "--no-headers"],
            "systemctl_status": ["systemctl", "status", params.get("service", "")],
            "journalctl_logs": ["journalctl", "--no-pager"],
            "netstat_connections": ["ss", "-tlnp"],
            "df_disk": ["df", "-h", "/"],
            "free_memory": ["free", "-h"],
            "get_services": ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
            "lsof_files": ["lsof", "-nP", "-i"],
            "rpm_verify": ["rpm", "-V", params.get("package", "")],
        }
        if tool_name == "journalctl_logs":
            argv = list(readonly[tool_name])
            if params.get("unit"):
                argv.extend(["-u", str(params["unit"])])
            argv.extend(["-n", str(params.get("lines", 50))])
            return argv, False
        if tool_name in readonly:
            return [str(v) for v in readonly[tool_name] if str(v) != ""], False

        writes: dict[str, list[Any]] = {
            "systemctl_restart": ["systemctl", "restart", params.get("service", "")],
            "journalctl_clean": ["journalctl", "--no-pager", "--vacuum-time", params.get("days", "7")],
            "kill_process": ["kill", f"-{int(params.get('signal', 15))}", params.get("pid", "")],
            "truncate_log": ["truncate", "-s", "0", params.get("path", "")],
        }
        if tool_name in writes:
            return [str(v) for v in writes[tool_name]], True
        raise ValueError(f"No runtime implementation for tool: {tool_name}")

    @staticmethod
    def _file_op(operation: str, params: dict) -> RuntimeResult:
        path = str(params.get("path", ""))
        content = str(params.get("content", ""))
        display = f"{'append_file' if operation == 'append' else 'create_file'} path={path}"
        if _running_as_root():
            return RuntimeResult(
                -1, "", "Refusing file operation while agent service runs as root", display
            )
        blocked = ("/etc", "/boot", "/sys", "/proc", "/root")
        if any(path == prefix or path.startswith(prefix + os.sep) for prefix in blocked):
            return RuntimeResult(-1, "", f"Path {path} is blocked", display)
        if os.path.islink(path):
            return RuntimeResult(-1, "", "Symlink targets are not allowed", display)
        try:
            snapshot_before_write(path, operation)
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            mode = "a" if operation == "append" else "w"
            with open(path, mode, encoding="utf-8") as handle:
                handle.write(content)
            result = {"status": "written", "path": path, "bytes": len(content)}
            return RuntimeResult(0, json.dumps(result, ensure_ascii=False), "", display)
        except Exception as exc:
            return RuntimeResult(1, "", str(exc)[:500], display)

    @staticmethod
    def _exec_script(params: dict, timeout: int) -> RuntimeResult:
        path = str(params.get("path", ""))
        display = f"execute_script path={path}"
        if _running_as_root():
            return RuntimeResult(-1, "", "Refusing script execution while service runs as root", display)
        raw_path = os.path.abspath(os.path.expanduser(path))
        if os.path.islink(raw_path):
            return RuntimeResult(-1, "", "Symlinks are not allowed", display)
        path = os.path.realpath(raw_path)
        allowed_dir = os.path.realpath("/tmp/kylin-agent")
        if path != allowed_dir and not path.startswith(allowed_dir + os.sep):
            return RuntimeResult(-1, "", f"Script must be under {allowed_dir}", display)
        if not os.path.isfile(path):
            return RuntimeResult(1, "", f"Not a file: {path}", display)
        try:
            mode = os.stat(path).st_mode
            if mode & 0o002:
                return RuntimeResult(-1, "", "World-writable scripts are not executable", display)
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                first_line = handle.readline().strip()
            if first_line.startswith("#!") and any(
                lang in first_line.lower() for lang in ("python", "perl", "ruby")
            ):
                return RuntimeResult(-1, "", f"Shebang rejected: {first_line}", display)
            result = subprocess.run(
                ["bash", path], capture_output=True, text=True, timeout=min(timeout, 30)
            )
            return RuntimeResult(result.returncode, result.stdout[:5000], result.stderr[:5000], display)
        except subprocess.TimeoutExpired:
            return RuntimeResult(-1, "", "Script execution timed out", display)
        except Exception as exc:
            return RuntimeResult(1, "", str(exc)[:500], display)

