"""GET /api/context + /api/posture + /health."""
import logging

import httpx
from fastapi import APIRouter, Request

from config import settings
from deps import perception, posture_engine, mcp_server

router = APIRouter()
logger = logging.getLogger("kylin-agent")


@router.get("/api/whoami")
async def whoami(request: Request):
    return {
        "user_id": getattr(request.state, "user_id", "anonymous"),
        "role": getattr(request.state, "role", "anonymous"),
        "key_id": getattr(request.state, "key_id", ""),
    }


@router.get("/api/context")
async def get_context(request: Request, user_id: str = "default"):
    role = getattr(request.state, "role", "anonymous")
    ctx = perception.build("status", user_id, role=role)
    system = ctx["system"]

    # Role-gated visibility
    if role == "anonymous":
        return {
            "system": {
                "disk": system.get("disk", {}),
                "memory": system.get("memory", {}),
            },
            "time": ctx["time"],
            "visibility": "basic",
            "hint": "Enter an API key to see processes, services, and connections.",
        }
    elif role == "viewer":
        return {
            "system": system,  # full read
            "time": ctx["time"],
            "visibility": "full_read",
        }
    else:  # operator, admin
        return {
            "system": system,
            "time": ctx["time"],
            "visibility": "full",
            "posture": posture_engine.posture_for_prompt() if role == "admin" else None,
        }


@router.get("/api/posture")
async def get_posture():
    return {
        "posture": posture_engine.posture,
        "threshold": posture_engine.threshold_for_posture(),
        "audit_intensity": posture_engine.audit_intensity(),
        "veto_count": posture_engine._veto_count,
        "drift_log": posture_engine._drift_log[-5:],
    }


@router.get("/health")
async def health():
    checks = {}
    healthy = True

    # DeepSeek API reachability
    if settings.agent_mode != "mock" and settings.deepseek_api_key:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(
                    f"{settings.deepseek_base_url}/models",
                    headers={"Authorization": f"Bearer {settings.deepseek_api_key}"},
                )
            reachable = resp.status_code < 500
            checks["deepseek_api"] = "reachable" if reachable else f"status {resp.status_code}"
            if not reachable:
                healthy = False
        except Exception as e:
            checks["deepseek_api"] = f"unreachable: {str(e)[:80]}"
            healthy = False
            logger.warning(f"Health check: DeepSeek API unreachable: {e}")
    else:
        checks["deepseek_api"] = "skipped (mock mode)"

    checks["provider_mode"] = settings.agent_mode
    checks["posture"] = posture_engine.posture
    checks["mcp_tools"] = len(mcp_server.registry.list_tools())

    return {
        "status": "healthy" if healthy else "degraded",
        "checks": checks,
    }
