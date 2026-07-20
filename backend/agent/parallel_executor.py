"""
Parallel tool executor — concurrent execution of independent diagnostic commands.
===============================================================================
Groups non-dependent tool calls and executes them concurrently.
Respects a max concurrency limit. Returns aggregated results in original order.
"""
from __future__ import annotations
import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout


MAX_CONCURRENCY = 4  # Max parallel tool executions
DEFAULT_TIMEOUT = 30  # Per-tool timeout in seconds


@dataclass
class ToolResult:
    tool_name: str
    params: dict
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""
    elapsed_ms: float = 0.0
    error: str = ""
    success: bool = True


@dataclass
class ParallelResult:
    results: list[ToolResult] = field(default_factory=list)
    total_elapsed_ms: float = 0.0
    success_count: int = 0
    failure_count: int = 0


class ParallelExecutor:
    """Execute independent tool calls concurrently with bounded parallelism."""

    def __init__(self, max_workers: int = MAX_CONCURRENCY):
        self._max_workers = min(max_workers, MAX_CONCURRENCY)
        self._pool = ThreadPoolExecutor(max_workers=self._max_workers)

    def execute_all(self, commands: list[dict],
                    executor_fn=None,
                    timeout_per_cmd: int = DEFAULT_TIMEOUT) -> ParallelResult:
        """Execute a list of tool commands in parallel.

        Args:
            commands: [{"tool": "ps_processes", "params": {}}, ...]
            executor_fn: function(tool_name, params) -> (exit_code, stdout, stderr)
            timeout_per_cmd: per-command timeout in seconds

        Returns:
            ParallelResult with results in original order.
        """
        if not commands:
            return ParallelResult()

        import time
        start = time.time()

        # Separate independent (no data dependency) from dependent commands
        # Heuristic: read-only commands (ps, df, free, ss, journalctl, lsof) are independent
        READ_ONLY_TOOLS = {"ps_processes", "df_disk", "free_memory", "netstat_connections",
                          "journalctl_logs", "systemctl_status", "get_services",
                          "lsof_files", "rpm_verify"}
        WRITE_TOOLS = {"create_file", "append_file", "execute_script",
                      "systemctl_restart", "journalctl_clean", "kill_process", "truncate_log"}

        independent = [c for c in commands
                      if c.get("tool", "") in READ_ONLY_TOOLS]
        dependent = [c for c in commands
                    if c.get("tool", "") in WRITE_TOOLS or c.get("tool", "") not in READ_ONLY_TOOLS]

        # Phase 1: Execute all independent read-only commands in parallel
        results = []
        if independent:
            futures = {}
            for i, cmd in enumerate(independent):
                tool = cmd.get("tool", "unknown")
                params = cmd.get("params", {})
                future = self._pool.submit(
                    self._execute_one, tool, params, executor_fn, timeout_per_cmd
                )
                futures[future] = i

            for future in concurrent.futures.as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result(timeout=timeout_per_cmd + 5)
                    results.append((idx, result))
                except FuturesTimeout:
                    results.append((idx, ToolResult(
                        tool_name=independent[idx].get("tool", "unknown"),
                        params=independent[idx].get("params", {}),
                        success=False,
                        error=f"Timeout after {timeout_per_cmd}s",
                    )))
                except Exception as e:
                    results.append((idx, ToolResult(
                        tool_name=independent[idx].get("tool", "unknown"),
                        params=independent[idx].get("params", {}),
                        success=False,
                        error=str(e),
                    )))

            # Restore original order
            results.sort(key=lambda x: x[0])
            phase1_results = [r for _, r in results]
        else:
            phase1_results = []

        # Phase 2: Execute write/sequential commands one at a time
        phase2_results = []
        for cmd in dependent:
            tool = cmd.get("tool", "unknown")
            params = cmd.get("params", {})
            result = self._execute_one(tool, params, executor_fn, timeout_per_cmd)
            phase2_results.append(result)

        all_results = phase1_results + phase2_results
        elapsed = (time.time() - start) * 1000

        return ParallelResult(
            results=all_results,
            total_elapsed_ms=elapsed,
            success_count=sum(1 for r in all_results if r.success),
            failure_count=sum(1 for r in all_results if not r.success),
        )

    def _execute_one(self, tool_name: str, params: dict,
                     executor_fn=None, timeout: int = 30) -> ToolResult:
        """Execute a single tool call with timeout."""
        import time
        start = time.time()

        try:
            if executor_fn:
                exit_code, stdout, stderr = executor_fn(tool_name, params, timeout)
            else:
                from agent.tools_manifest import lookup_by_llm_name
                entry = lookup_by_llm_name(tool_name)
                if entry is None or entry.get("risk") != "readonly":
                    raise PermissionError(
                        "ParallelExecutor fallback only permits manifest read-only tools; "
                        "writes require ExecutionGateway"
                    )
                from security.sandbox import execute
                cmd_str = self._build_command(tool_name, params)
                exit_code, stdout, stderr = execute(cmd_str, timeout)

            return ToolResult(
                tool_name=tool_name,
                params=params,
                exit_code=exit_code,
                stdout=stdout[:5000] if stdout else "",
                stderr=stderr[:1000] if stderr else "",
                elapsed_ms=(time.time() - start) * 1000,
                success=(exit_code == 0),
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                params=params,
                success=False,
                error=str(e),
                elapsed_ms=(time.time() - start) * 1000,
            )

    def _build_command(self, tool_name: str, params: dict) -> str:
        """Build shell command from tool name + params (fallback)."""
        from agent.tools_manifest import lookup_by_llm_name
        entry = lookup_by_llm_name(tool_name)
        command_template = entry.get("command", tool_name) if entry else tool_name
        for k, v in params.items():
            command_template = command_template.replace(f"{{{k}}}", str(v))
        return command_template

    def shutdown(self):
        self._pool.shutdown(wait=False)
