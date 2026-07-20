"""MCP methods, including guarded external resource reads."""
from __future__ import annotations

import json

from mcp.registry import ToolRegistry


class MCPHandlers:
    def __init__(self, registry: ToolRegistry, output_guard=None):
        self.registry = registry
        self.output_guard = output_guard

    def handle(self, method: str, params: dict, security_context: dict | None = None) -> dict:
        security_context = security_context or {}
        if method == "initialize":
            return {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "kylin-agent", "version": "1.7.0"},
                "capabilities": {"tools": {}, "resources": {}},
            }
        if method == "initialized":
            return {}
        if method == "tools/list":
            return {"tools": self.registry.list_tools()}
        if method == "tools/call":
            return self.registry.call(
                params.get("name", ""),
                params.get("arguments", {}),
                security_context=security_context,
            )
        if method == "resources/list":
            return {"resources": [
                {"uri": "os://processes", "name": "Process List", "mimeType": "application/json"},
                {"uri": "os://services", "name": "Service States", "mimeType": "application/json"},
                {"uri": "os://disk", "name": "Disk Usage", "mimeType": "application/json"},
                {"uri": "os://memory", "name": "Memory Usage", "mimeType": "application/json"},
                {"uri": "os://connections", "name": "Network Connections", "mimeType": "application/json"},
            ]}
        if method == "resources/read":
            return self._read_resource(params.get("uri", ""), security_context)
        return {"error": f"Unknown method: {method}"}

    def _read_resource(self, uri: str, security_context: dict) -> dict:
        from config import settings
        from perception.os_sensors import MockOSSensor, RealOSSensor

        sensor = RealOSSensor() if settings.agent_mode != "mock" else MockOSSensor()
        resource_map = {
            "os://processes": lambda: {"processes": sensor.get_processes()},
            "os://services": lambda: {"services": sensor.get_services()},
            "os://disk": lambda: {"disk": sensor.get_disk()},
            "os://memory": lambda: {"memory": sensor.get_memory()},
            "os://connections": lambda: {"connections": sensor.get_connections()},
        }
        handler = resource_map.get(uri)
        if handler is None:
            return {"contents": [{"uri": uri, "text": f"Unknown resource: {uri}"}], "isError": True}
        data = handler()
        security = {"action": "pass"}
        if self.output_guard is not None:
            inspected = self.output_guard.inspect_object(
                data,
                "mcp_resource",
                f"resources/read:{uri}",
                str(security_context.get("trace_id", "")),
            )
            data = inspected.sanitized_content
            security = inspected.security_metadata()
        return {
            "contents": [{"uri": uri, "text": json.dumps(data, ensure_ascii=False, default=str)}],
            "isError": security.get("action") == "block",
            "output_security": security,
        }

