"""GET /api/session/{id} — session info and conversation history."""
from fastapi import APIRouter, Request

from deps import session_store

router = APIRouter()


@router.get("/api/session/{session_id}")
async def get_session(request: Request, session_id: str):
    session = session_store.get(session_id)
    if session is None:
        return {"error": "session not found", "session_id": session_id}
    return {
        "session_id": session["session_id"],
        "user_id": session["user_id"],
        "created_at": session["created_at"],
        "last_access": session["last_access"],
        "history": list(session["history"]),
        "turn_count": len(session["history"]),
    }
