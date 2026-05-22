"""MCP method handlers."""
from mcp.registry import ToolRegistry


class MCPHandlers:
    def __init__(self, registry: ToolRegistry):
        self.registry = registry

    def handle(self, method: str, params: dict) -> dict:
        if method == "initialize":
            return {
                "protocolVersion": "0.1.0",
                "serverInfo": {"name": "kylin-agent", "version": "0.1.0"},
                "capabilities": {"tools": {}},
            }
        elif method == "initialized":
            return {}
        elif method == "tools/list":
            return {"tools": self.registry.list_tools()}
        elif method == "tools/call":
            name = params.get("name", "")
            arguments = params.get("arguments", {})
            return self.registry.call(name, arguments)
        elif method == "resources/list":
            return {"resources": [
                {"uri": "os://processes", "name": "Process List", "mimeType": "application/json"},
                {"uri": "os://services", "name": "Service States", "mimeType": "application/json"},
                {"uri": "os://disk", "name": "Disk Usage", "mimeType": "application/json"},
                {"uri": "os://memory", "name": "Memory Usage", "mimeType": "application/json"},
                {"uri": "os://connections", "name": "Network Connections", "mimeType": "application/json"},
            ]}
        elif method == "resources/read":
            uri = params.get("uri", "")
            return {"contents": [{"uri": uri, "text": "Resource data via /api/context"}]}
        else:
            return {"error": f"Unknown method: {method}"}
