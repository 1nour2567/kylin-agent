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
    "/api/posture", "/api/whoami",
}
key_store = KeyStore()


class BearerTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Authenticate or set default identity
        info = self._authenticate(request)
        has_any_auth = bool(settings.api_key or key_store.list_entries())

        if info:
            request.state.user_id = info["user_id"]
            request.state.role = info["role"]
            request.state.key_id = info["key_id"]
        elif not has_any_auth:
            # Dev mode: no keys configured — allow anonymous viewer (#14)
            request.state.user_id = "anonymous"
            request.state.role = "viewer"
            request.state.key_id = "key_none"
        else:
            # Keys exist but no valid Bearer token — no access
            request.state.user_id = "anonymous"
            request.state.role = "anonymous"
            request.state.key_id = ""

        # Public paths + frontend — always pass
        public_paths = set(PUBLIC_PATHS)
        if settings.allow_anonymous_read:
            public_paths.update({
                "/api/context", "/api/mcp/tools", "/api/inspect/history",
            })

        if path in public_paths:
            return await call_next(request)
        if path == "/" or path.startswith("/src"):
            return await call_next(request)

        # /api/* and /mcp — check auth
        if path.startswith("/api") or path.startswith("/mcp"):
            role = getattr(request.state, "role", "anonymous")
            if role == "anonymous":
                return JSONResponse(
                    status_code=401,
                    content={"error": "unauthorized",
                             "detail": "Authentication required. Create API keys or set API_KEY in .env"},
                )

        return await call_next(request)

    @staticmethod
    def _authenticate(request: Request) -> Optional[dict]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token = auth[7:]
        return key_store.validate(token)
