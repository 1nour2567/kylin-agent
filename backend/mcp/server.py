"""MCP JSON-RPC Server — SSE transport for B/S architecture."""
import json
from mcp.handlers import MCPHandlers
from mcp.registry import ToolRegistry


class MCPServer:
    def __init__(self):
        self.registry = ToolRegistry()
        self.handlers = MCPHandlers(self.registry)

    def dispatch(self, raw_message: str) -> str:
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        result = self.handlers.handle(method, params)
        if "error" in result:
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": result["error"]})
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def register_tool(self, name: str, description: str, parameters: dict, handler):
        self.registry.register(name, description, parameters, handler)
