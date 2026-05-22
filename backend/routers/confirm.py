"""POST /api/confirm + GET /api/pending."""
from fastapi import APIRouter, Request
from pydantic import BaseModel

from deps import _pending_confirmations, cleanup_pending, logger
from security.sandbox import execute_restricted
from audit.trail import AuditTrail

router = APIRouter()


class ConfirmRequest(BaseModel):
    event_id: str
    confirmed: bool


@router.post("/api/confirm")
async def confirm(request: Request, req: ConfirmRequest):
    cleanup_pending()

    # Server-verified identity
    user_id = getattr(request.state, "user_id", "anonymous")
    role = getattr(request.state, "role", "viewer")

    # Viewer role can never execute confirm-tier commands — hard block
    if role == "viewer":
        return {"status": "denied", "event_id": req.event_id,
                "message": "Viewer role cannot execute write operations. Request an operator or admin."}

    pending = _pending_confirmations.pop(req.event_id)

    if not pending:
        return {"status": "not_found", "message": f"No pending confirmation for {req.event_id}"}

    # Prevent cross-user hijacking: only the intended user or an admin can confirm
    pending_user = pending.get("user_id", "")
    if pending_user and user_id != pending_user and role != "admin":
        return {"status": "denied", "event_id": req.event_id,
                "message": f"This confirmation belongs to user '{pending_user}', not '{user_id}'."}

    trail = AuditTrail(user_id)

    if not req.confirmed:
        trail.chain_close("denied_by_user", {
            "event_id": req.event_id,
            "command": pending["command"],
        })
        return {"status": "denied", "event_id": req.event_id,
                "message": "Command execution denied by user"}

    cmd = pending["command"]
    trail.chain_close("user_confirmed", {"event_id": req.event_id, "command": cmd})
    exit_code, stdout, stderr = execute_restricted(cmd, timeout=30)
    logger.info(f"confirm_exec user={user_id} cmd={cmd} exit={exit_code}")
    trail.execute(cmd, exit_code, stdout, stderr)

    return {
        "status": "executed",
        "event_id": req.event_id,
        "command": cmd,
        "exit_code": exit_code,
        "stdout": stdout[:2000],
        "stderr": stderr[:500] if exit_code != 0 else "",
    }


@router.get("/api/pending")
async def list_pending(request: Request, user_id: str = ""):
    cleanup_pending()
    verified_user = getattr(request.state, "user_id", "anonymous")
    effective_user = user_id or verified_user
    items = _pending_confirmations.items_for_user(effective_user)
    return {"pending": items, "count": len(items)}
