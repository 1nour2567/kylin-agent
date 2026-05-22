"""Bearer Token authentication middleware.

Supports two auth modes:
  - API_KEY in .env → single admin key (development / backward-compat)
  - KeyStore → multi-user keys with role assignment (production)

Each request gets request.state: user_id, role, key_id.
"""
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import settings
from auth.key_store import KeyStore

logger = logging.getLogger("kylin-agent")

PUBLIC_PATHS = {
    "/health", "/docs", "/openapi.json", "/redoc",
    "/api/posture", "/api/mcp/tools", "/api/whoami", "/api/context",
    "/api/inspect/history",
}
key_store = KeyStore()


class BearerTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Try to authenticate for all paths (sets identity on public paths too)
        info = self._authenticate(request)
        if info:
            request.state.user_id = info["user_id"]
            request.state.role = info["role"]
            request.state.key_id = info["key_id"]

        # Public paths + frontend — always pass
        if path in PUBLIC_PATHS:
            return await call_next(request)
        if path == "/" or path.startswith("/src"):
            return await call_next(request)

        # /api/* and /mcp — require auth
        if path.startswith("/api") or path.startswith("/mcp"):
            if info is None:
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized", "detail": "Missing or invalid Bearer token"},
                )

        return await call_next(request)

    @staticmethod
    def _authenticate(request: Request) -> Optional[dict]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            # No Bearer token → check if auth is disabled
            if not settings.api_key and not key_store.list_entries():
                return {"user_id": "anonymous", "role": "viewer", "key_id": "key_none"}
            return None

        token = auth[7:]
        return key_store.validate(token)
