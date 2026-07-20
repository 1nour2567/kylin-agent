"""MCP JSON-RPC 2.0 protocol types."""
from typing import Any, Dict
from pydantic import BaseModel


class ToolSchema(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any] = {}
