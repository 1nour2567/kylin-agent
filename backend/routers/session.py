"""GET /api/session/{id} — session info and conversation history."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from deps import session_store

router = APIRouter()


@router.get("/api/session/{session_id}")
async def get_session(request: Request, session_id: str):
    user_id = getattr(request.state, "user_id", "anonymous")
    role = getattr(request.state, "role", "viewer")
    session = session_store.get(session_id, user_id)
    if session is None:
        return {"error": "session not found", "session_id": session_id}
    # Non-owner and non-admin: return 403 (#08)
    if session.get("user_id") != user_id and role != "admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return {
        "session_id": session["session_id"],
        "user_id": session["user_id"],
        "created_at": session["created_at"],
        "last_access": session["last_access"],
        "history": list(session["history"]),
        "turn_count": len(session["history"]),
    }
