"""GET /api/audit/* — FOIA-style audit endpoints. Admin-only by default."""
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from audit.foia import query_trail, get_event, verify_day

router = APIRouter()


def _is_not_admin(request: Request):
    role = getattr(request.state, "role", "viewer")
    return role != "admin"


@router.get("/api/audit/trail")
async def audit_trail(request: Request,
                      from_date: str = "2026-01-01", to_date: str = "2099-12-31",
                      limit: int = 100):
    if _is_not_admin(request):
        return JSONResponse(status_code=403, content={"error": "Audit access requires admin role"})
    return query_trail(from_date, to_date, limit)


@router.get("/api/audit/event/{event_id}")
async def audit_event(request: Request, event_id: str):
    if _is_not_admin(request):
        return JSONResponse(status_code=403, content={"error": "Audit access requires admin role"})
    return get_event(event_id)


@router.get("/api/audit/verify")
async def audit_verify(request: Request, date: str = ""):
    if _is_not_admin(request):
        return JSONResponse(status_code=403, content={"error": "Audit access requires admin role"})
    d = date or datetime.now().strftime("%Y-%m-%d")
    return verify_day(d)
