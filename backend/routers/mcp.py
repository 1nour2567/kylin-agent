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
    result = mcp_server.dispatch(raw)
    return Response(content=result, media_type="application/json")


@router.get("/api/mcp/tools")
async def list_mcp_tools():
    return {"tools": mcp_server.registry.list_tools()}
