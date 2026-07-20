"""Single execution path for chat, stream, agent loop, confirm, and MCP."""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Optional

from agent.tool_runtime import ToolRuntime
from agent.tools_manifest import lookup_by_llm_name
from security.capability_token import (
    CapabilityScope,
    CapabilityTokenService,
    canonicalize_params,
)
from security.indirect_injection import ToolOutputGuard


@dataclass
class ExecutionResult:
    tool_name: str
    canonical_params: dict
    exit_code: int
    sanitized_stdout: str
    sanitized_stderr: str
    elapsed_ms: float
    capability_verification: dict = field(default_factory=dict)
    output_security: dict = field(default_factory=dict)
    command: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def blocked_by_ipi(self) -> bool:
        return self.output_security.get("action") == "block"


class ExecutionGateway:
    def __init__(
        self,
        capability_token_service: CapabilityTokenService,
        tool_output_guard: ToolOutputGuard,
        runtime: ToolRuntime,
    ):
        self.capability_token_service = capability_token_service
        self.tool_output_guard = tool_output_guard
        self.runtime = runtime

    def execute_tool(
        self,
        tool_name: str,
        params: Optional[dict],
        actor_context: dict,
        capability_token: Optional[str] = None,
        expected_scope: CapabilityScope | dict | None = None,
        timeout: int = 30,
    ) -> ExecutionResult:
        started = time.perf_counter()
        try:
            canonical, canonical_params = canonicalize_params(tool_name, params)
        except Exception as exc:
            return self._denied(str(tool_name), {}, f"normalization_failed: {exc}", started)

        entry = lookup_by_llm_name(canonical)
        if entry is None:
            return self._denied(canonical, canonical_params, "unknown_tool", started)
        if entry.get("exec_tier") == "veto" or not entry.get("llm_name"):
            return self._denied(canonical, canonical_params, "veto_tool", started)

        capability_required = entry.get("risk") != "readonly"
        verification = {"valid": True, "reason": "not_required", "jti": "", "scope_digest": ""}
        if capability_required:
            if not capability_token or expected_scope is None:
                return self._denied(
                    canonical, canonical_params, "capability_required", started,
                    {"valid": False, "reason": "capability_required"},
                )
            try:
                saved_scope = (
                    expected_scope
                    if isinstance(expected_scope, CapabilityScope)
                    else CapabilityScope.from_dict(expected_scope)
                )
                rebuilt_scope = self.capability_token_service.build_scope(
                    canonical,
                    canonical_params,
                    actor_context,
                    trace_id=saved_scope.trace_id,
                    operation_id=saved_scope.operation_id,
                    event_id=saved_scope.event_id,
                    single_use=saved_scope.single_use,
                )
                if not self.capability_token_service.scopes_match(saved_scope, rebuilt_scope):
                    return self._denied(
                        canonical, canonical_params, "expected_scope_mismatch", started,
                        {"valid": False, "reason": "expected_scope_mismatch"},
                    )
                verified = self.capability_token_service.verify_and_consume(
                    capability_token, rebuilt_scope
                )
                verification = verified.public_dict()
                if not verified.valid:
                    return self._denied(
                        canonical, canonical_params, verified.reason, started, verification
                    )
            except Exception as exc:
                return self._denied(
                    canonical, canonical_params, f"capability_validation_failed: {exc}", started,
                    {"valid": False, "reason": "capability_validation_failed"},
                )

        try:
            runtime_result = self.runtime.execute(canonical, canonical_params, timeout=timeout)
        except Exception as exc:
            runtime_result = type("RuntimeFailure", (), {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(exc),
                "command_display": canonical,
            })()

        trace_id = str(actor_context.get("trace_id") or "")
        stdout_security = self.tool_output_guard.inspect_text(
            runtime_result.stdout, "tool_stdout", canonical, trace_id
        )
        stderr_security = self.tool_output_guard.inspect_text(
            runtime_result.stderr, "tool_stderr", canonical, trace_id
        )
        output_security = self._combine_output_security(stdout_security, stderr_security)

        return ExecutionResult(
            tool_name=canonical,
            canonical_params=canonical_params,
            exit_code=int(runtime_result.exit_code),
            sanitized_stdout=str(stdout_security.sanitized_content),
            sanitized_stderr=str(stderr_security.sanitized_content),
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            capability_verification=verification,
            output_security=output_security,
            command=str(runtime_result.command_display),
        )

    @staticmethod
    def _combine_output_security(stdout_result, stderr_result) -> dict:
        priority = {"pass": 0, "sanitize": 1, "block": 2}
        strongest = max(
            (stdout_result, stderr_result), key=lambda item: priority.get(item.action, 0)
        )
        return {
            "action": strongest.action,
            "risk_score": max(stdout_result.risk_score, stderr_result.risk_score),
            "risk_level": strongest.risk_level,
            "reason": strongest.reason,
            "matched_patterns": sorted(set(
                stdout_result.matched_patterns + stderr_result.matched_patterns
            )),
            "ref": strongest.ref,
            "stdout_ref": stdout_result.ref,
            "stderr_ref": stderr_result.ref,
        }

    @staticmethod
    def _denied(
        tool_name: str,
        params: dict,
        reason: str,
        started: float,
        verification: Optional[dict] = None,
    ) -> ExecutionResult:
        return ExecutionResult(
            tool_name=tool_name,
            canonical_params=params,
            exit_code=-1,
            sanitized_stdout="",
            sanitized_stderr=f"Execution denied: {reason}",
            elapsed_ms=round((time.perf_counter() - started) * 1000, 3),
            capability_verification=verification or {"valid": False, "reason": reason},
            output_security={
                "action": "pass",
                "risk_score": 0,
                "risk_level": "low",
                "reason": "not_executed",
                "matched_patterns": [],
                "ref": "",
            },
            command=tool_name,
        )

