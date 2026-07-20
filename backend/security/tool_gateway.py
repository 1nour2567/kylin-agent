"""Security gateway for MCP tools, sharing CapBAC with all other entry points."""
from __future__ import annotations

import secrets
import time
from typing import Any, Callable

from agent.tools_manifest import lookup_by_mcp_name
from audit.trail import AuditTrail
from security.redaction import redact_obj, redact_text


class ToolSecurityGateway:
    def __init__(
        self,
        guardrail,
        posture_engine,
        pending_store,
        logger,
        clock: Callable[[], float] | None = None,
        capability_token_service=None,
        execution_gateway=None,
        output_guard=None,
    ):
        self.guardrail = guardrail
        self.posture_engine = posture_engine
        self.pending_store = pending_store
        self.logger = logger
        self.clock = clock or time.time
        self.capability_token_service = capability_token_service
        self.execution_gateway = execution_gateway
        self.output_guard = output_guard

    def authorize_mcp(self, tool_name: str, arguments: dict, context: dict | None = None) -> dict:
        context = dict(context or {})
        arguments = dict(arguments or {})
        user_id = str(context.get("user_id") or "anonymous")
        role = str(context.get("role") or "viewer")
        trace_id = str(context.get("trace_id") or f"tr_mcp_{secrets.token_hex(12)}")
        context.update({"user_id": user_id, "role": role, "trace_id": trace_id})

        trail = AuditTrail(user_id, role=role)
        trail.receive(f"MCP tools/call {tool_name} {redact_obj(arguments)}")
        entry = lookup_by_mcp_name(tool_name)
        if not entry:
            trail.chain_close("mcp_vetoed", {"tool": tool_name, "reason": "unknown_tool"})
            return self._deny(f"MCP tool '{tool_name}' is not registered in the manifest")

        llm_tool = entry.get("llm_name") or tool_name
        self.guardrail.posture = self.posture_engine.posture
        gr = self.guardrail.validate_commands(
            [{"tool": llm_tool, "params": arguments}],
            role=role,
            intent_profile={"source": "mcp", "risk_hint": "external_tool_call"},
            actor_context=context,
            trace_id=trace_id,
        )
        trail.validate(gr.command_results)
        if not gr.command_results:
            return self._deny("MCP security validation produced no command result")
        command_result = gr.command_results[0]
        if not gr.passed:
            self.posture_engine.on_veto()
            reason = gr.blocked_at or command_result.get("reason", "blocked")
            trail.chain_close("mcp_vetoed", {"tool": tool_name, "blocked_at": reason})
            return self._deny(reason, command_result)

        # Every MCP write waits for the existing /api/confirm flow.  The token
        # is intentionally not issued on this external surface.
        if command_result.get("capability_required"):
            if role == "viewer":
                return self._deny("Viewer role cannot execute write operations through MCP", command_result)
            if self.capability_token_service is not None and not command_result.get("capability_scope"):
                return self._deny("Capability scope missing for MCP write operation", command_result)
            event_id = self._create_pending(tool_name, command_result, context)
            trail.chain_close("mcp_confirmation_required", {
                "tool": tool_name,
                "pending_id": event_id,
                "trace_id": trace_id,
            })
            return {
                "allowed": False,
                "mcp_result": {
                    "content": [{
                        "type": "text",
                        "text": (
                            "MCP tool call requires human confirmation. "
                            f"Confirm with /api/confirm event_id={event_id}."
                        ),
                    }],
                    "isError": False,
                    "requires_confirmation": True,
                    "pending_event_id": event_id,
                    "security": command_result,
                },
            }

        self.posture_engine.on_permit()
        decision = {"allowed": True, "security": command_result}
        if self.execution_gateway is not None:
            execution = self.execution_gateway.execute_tool(
                command_result["canonical_tool"],
                command_result["canonical_params"],
                context,
                timeout=30,
            )
            decision["execution_result"] = execution.to_dict()
        return decision

    def record_mcp_execution(
        self,
        tool_name: str,
        arguments: dict,
        context: dict | None,
        decision: dict | None,
        result: Any,
        is_error: bool,
    ) -> None:
        context = context or {}
        trail = AuditTrail(context.get("user_id", "anonymous"), role=context.get("role", "viewer"))
        command = (decision or {}).get("security", {}).get("canonical_tool", tool_name)
        if isinstance(result, dict):
            stdout = str(result.get("sanitized_stdout", result))
            stderr = str(result.get("sanitized_stderr", ""))
            exit_code = int(result.get("exit_code", 1 if is_error else 0))
        else:
            stdout, stderr, exit_code = redact_text(str(result))[:1000], "", 1 if is_error else 0
        trail.execute(f"MCP:{command}", exit_code, stdout, stderr)
        trail.chain_close("mcp_completed", {
            "tool": tool_name,
            "is_error": is_error,
            "arguments": redact_obj(arguments or {}),
        })

    def _create_pending(self, mcp_tool: str, command_result: dict, context: dict) -> str:
        now = self.clock()
        event_id = command_result.get("event_id") or f"evt_{secrets.token_hex(12)}"
        params = dict(command_result.get("canonical_params") or {})
        self.pending_store.add(event_id, {
            "command": command_result.get("canonical_tool", mcp_tool),
            "display_command": command_result.get("display_command", mcp_tool),
            "risk_label": command_result.get("risk_label", "?"),
            "user_id": context.get("user_id", "anonymous"),
            "role": context.get("role", "viewer"),
            "created_at": now,
            "posture": self.posture_engine.posture,
            "source": "mcp",
            "mcp_tool": mcp_tool,
            "tool_name": command_result.get("canonical_tool", mcp_tool),
            "params": params,
            "trace_id": command_result.get("trace_id", context.get("trace_id", "")),
            "operation_id": command_result.get("operation_id", ""),
            "event_id": event_id,
            "capability_scope": command_result.get("capability_scope"),
            "file_path": str(params.get("path", "")),
            "operation": command_result.get("canonical_tool", mcp_tool),
            "target_fingerprint": {
                "path": params.get("path", ""),
                "pid": params.get("pid", ""),
                "service": params.get("service", ""),
                "snapshot_time": now,
            },
        })
        return event_id

    @staticmethod
    def _deny(reason: str, command_result: dict | None = None) -> dict:
        return {
            "allowed": False,
            "mcp_result": {
                "content": [{"type": "text", "text": redact_text(reason)}],
                "isError": True,
                "security": command_result or {},
            },
        }

