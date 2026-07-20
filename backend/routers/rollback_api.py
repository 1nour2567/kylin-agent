"""Rollback API — restore, list, stats, cleanup."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from security.sandbox import get_rollback

router = APIRouter()


def _is_admin(request: Request) -> bool:
    role = getattr(request.state, "role", "viewer")
    return role == "admin"


@router.get("/api/rollback/list")
async def rollback_list(request: Request):
    """List all rollback entries (admin only)."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    rm = get_rollback()
    return {"entries": rm.list_entries()}


@router.get("/api/rollback/restorable")
async def rollback_restorable(request: Request):
    """List unrestored entries available for rollback."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    rm = get_rollback()
    return {"entries": rm.list_restorable()}


@router.post("/api/rollback/restore/{entry_id}")
async def rollback_restore(request: Request, entry_id: str):
    """Restore a file from a specific rollback entry (admin only)."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    rm = get_rollback()
    result = rm.restore(entry_id)
    if result["success"]:
        return result
    return JSONResponse(status_code=404, content=result)


@router.post("/api/rollback/restore-last")
async def rollback_restore_last(request: Request):
    """Restore the most recent backup for a given file path."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    body = await request.json()
    path = body.get("path", "")
    if not path:
        return JSONResponse(status_code=400, content={"error": "path is required"})
    rm = get_rollback()
    result = rm.restore_last(path)
    if result["success"]:
        return result
    return JSONResponse(status_code=404, content=result)


@router.get("/api/rollback/stats")
async def rollback_stats(request: Request):
    """Rollback store statistics."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    rm = get_rollback()
    return rm.stats()


@router.get("/api/idempotency/stats")
async def idempotency_stats(request: Request):
    """Idempotency guard statistics."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    from security.idempotency import get_idempotency_guard
    return get_idempotency_guard().stats()


@router.post("/api/rollback/cleanup")
async def rollback_cleanup(request: Request):
    """Clean up expired rollback entries."""
    if not _is_admin(request):
        return JSONResponse(status_code=403, content={"error": "Admin required"})
    body = await request.json()
    days = body.get("days", 7)
    rm = get_rollback()
    return rm.cleanup(older_than_days=days)
