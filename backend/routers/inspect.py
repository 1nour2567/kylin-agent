"""GET /api/inspect — proactive inspection results."""
from fastapi import APIRouter

from deps import proactive_inspector, baseline_learner

router = APIRouter()


@router.get("/api/inspect")
async def inspect():
    """Latest inspection result + baseline anomaly tie-in."""
    latest = proactive_inspector.latest()
    anomalies = proactive_inspector.check_anomaly_tie_in(baseline_learner)
    return {
        "latest": latest,
        "baseline_anomalies": anomalies,
        "active_alerts": proactive_inspector.active_alerts(),
    }


@router.get("/api/inspect/history")
async def inspect_history(n: int = 10):
    return {"history": proactive_inspector.recent(min(n, 100))}
