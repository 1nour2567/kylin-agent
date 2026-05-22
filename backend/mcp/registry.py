"""MCP Tool Registry — wraps OS tools for MCP protocol."""
from typing import Callable, Dict, List


class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, dict] = {}

    def register(self, name: str, description: str, parameters: dict, handler: Callable):
        self._tools[name] = {
            "name": name,
            "description": description,
            "inputSchema": {
                "type": "object",
                "properties": {k: {"type": v} for k, v in parameters.items()},
                "required": list(parameters.keys()),
            },
            "handler": handler,
        }

    def list_tools(self) -> List[dict]:
        return [
            {"name": t["name"], "description": t["description"], "inputSchema": t["inputSchema"]}
            for t in self._tools.values()
        ]

    def call(self, name: str, arguments: dict) -> dict:
        tool = self._tools.get(name)
        if tool is None:
            return {"error": f"Tool '{name}' not found"}
        try:
            result = tool["handler"](**arguments)
            return {"content": [{"type": "text", "text": str(result)}], "isError": False}
        except Exception as e:
            return {"content": [{"type": "text", "text": str(e)}], "isError": True}
