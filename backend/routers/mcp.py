"""POST /mcp + GET /api/mcp/tools."""
from fastapi import APIRouter, Request
from fastapi.responses import Response

from deps import mcp_server, limiter

router = APIRouter()


@router.post("/mcp")
@limiter.limit("10/minute")
async def mcp_endpoint(request: Request):
    body = await request.body()
    raw = body.decode("utf-8")
    result = mcp_server.dispatch(raw, security_context={
        "user_id": getattr(request.state, "user_id", "anonymous"),
        "role": getattr(request.state, "role", "viewer"),
        "key_id": getattr(request.state, "key_id", ""),
        "client": request.client.host if request.client else "",
    })
    return Response(content=result, media_type="application/json")


@router.get("/api/mcp/tools")
async def list_mcp_tools():
    return {"tools": mcp_server.registry.list_tools()}
