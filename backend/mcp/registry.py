"""MCP tool registry with security interception and structure-preserving output guard."""
from __future__ import annotations

import json
from typing import Callable, Dict, List

from security.redaction import redact_obj, redact_text


_PY_TO_JSONSCHEMA = {
    "str": {"type": "string"}, "string": {"type": "string"},
    "int": {"type": "integer"}, "integer": {"type": "integer"},
    "float": {"type": "number"}, "number": {"type": "number"},
    "bool": {"type": "boolean"}, "boolean": {"type": "boolean"},
    "list": {"type": "array", "items": {"type": "string"}},
    "dict": {"type": "object"},
}


def _build_input_schema(params: dict, required: list | None = None) -> dict:
    properties = {
        name: _PY_TO_JSONSCHEMA.get(pytype, {"type": "string"})
        for name, pytype in params.items()
    }
    schema = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


class ToolRegistry:
    def __init__(self, output_guard=None):
        self._tools: Dict[str, dict] = {}
        self.security_gate = None
        self.audit_hook = None
        self.output_guard = output_guard

    def register(self, name: str, description: str, parameters: dict, handler: Callable,
                 optional_params: list | None = None):
        optional = set(optional_params or [])
        required = [key for key in parameters if key not in optional]
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": _build_input_schema(parameters, required or None),
            "handler": handler,
        }

    def list_tools(self) -> List[dict]:
        return [
            {"name": tool["name"], "description": tool["description"], "inputSchema": tool["inputSchema"]}
            for tool in self._tools.values()
        ]

    def call(self, name: str, arguments: dict, security_context: dict | None = None) -> dict:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"Tool '{name}' not found"}

        # A registry accidentally constructed without the shared security gate
        # must still be unable to invoke any state-changing handler.
        if self.security_gate is None:
            from agent.tools_manifest import lookup_by_mcp_name
            manifest_entry = lookup_by_mcp_name(name)
            if manifest_entry is not None and manifest_entry.get("risk") != "readonly":
                return {
                    "content": [{"type": "text", "text": "Write tool requires the shared security gateway"}],
                    "isError": True,
                }

        decision = None
        context = security_context or {}
        if self.security_gate is not None:
            decision = self.security_gate(name, arguments or {}, context)
            if not decision.get("allowed", False):
                return decision.get("mcp_result", {
                    "content": [{"type": "text", "text": "Tool call blocked by security policy"}],
                    "isError": True,
                })

        is_error = False
        if decision and "execution_result" in decision:
            result = decision["execution_result"]
            is_error = result.get("exit_code", -1) != 0 or result.get("output_security", {}).get("action") == "block"
            safe_result = redact_obj(result)
        else:
            try:
                result = tool["handler"](**(arguments or {}))
                if self.output_guard is not None:
                    inspected = self.output_guard.inspect_object(
                        result, "mcp_tool_result", name, str(context.get("trace_id", ""))
                    )
                    result = inspected.sanitized_content
                    is_error = inspected.action == "block"
                    security = inspected.security_metadata()
                else:
                    security = {"action": "pass"}
                safe_result = {"result": redact_obj(result), "output_security": security}
            except Exception as exc:
                is_error = True
                result = exc
                safe_result = {"error": redact_text(str(exc))}

        response = {
            "content": [{"type": "text", "text": json.dumps(safe_result, ensure_ascii=False, default=str)}],
            "isError": is_error,
        }
        if self.audit_hook is not None:
            try:
                self.audit_hook(name, arguments or {}, context, decision, safe_result, is_error)
            except Exception:
                pass
        return response
