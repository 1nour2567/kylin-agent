"""GET /api/baseline + POST /api/baseline/check — behavioral anomaly detection."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from deps import baseline_learner

router = APIRouter()


def _require_admin(request: Request):
    role = getattr(request.state, "role", "viewer")
    return role != "admin"


@router.get("/api/baseline")
async def get_baseline(request: Request):
    """Return the rolling baseline summary (profile count + last N days)."""
    if _require_admin(request):
        return JSONResponse(status_code=403, content={"error": "Baseline access requires admin role"})
    return {
        "profile_count": baseline_learner.profile_count(),
        "anomaly_check": baseline_learner.check_anomaly(),
    }


@router.get("/api/baseline/profiles")
async def list_profiles(request: Request):
    """List stored daily profiles."""
    if _require_admin(request):
        return JSONResponse(status_code=403, content={"error": "Baseline access requires admin role"})
    return {"profiles": baseline_learner._profiles}
