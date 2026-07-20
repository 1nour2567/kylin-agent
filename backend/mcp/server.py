"""MCP JSON-RPC Server — SSE transport for B/S architecture."""
import json
from mcp.handlers import MCPHandlers
from mcp.registry import ToolRegistry


class MCPServer:
    def __init__(self, output_guard=None):
        self.registry = ToolRegistry(output_guard=output_guard)
        self.handlers = MCPHandlers(self.registry, output_guard=output_guard)

    def dispatch(self, raw_message: str, security_context: dict | None = None) -> str:
        try:
            msg = json.loads(raw_message)
        except json.JSONDecodeError:
            return json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params", {})

        result = self.handlers.handle(method, params, security_context=security_context)
        if "error" in result:
            return json.dumps({"jsonrpc": "2.0", "id": msg_id, "error": result["error"]})
        return json.dumps({"jsonrpc": "2.0", "id": msg_id, "result": result})

    def register_tool(self, name: str, description: str, parameters: dict, handler,
                      optional_params: list = None):
        self.registry.register(name, description, parameters, handler,
                               optional_params=optional_params)
