"""Kylin OS Security Agent API — FastAPI application entry point."""
import json
import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response, FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from config import settings
from deps import limiter, posture_engine, register_mcp_tools, baseline_learner, proactive_inspector, logger
from middleware.auth import BearerTokenMiddleware
from routers import (
    chat_router, confirm_router, audit_router, mcp_router, system_router, ws_router,
    session_router, stream_router, baseline_router, inspect_router, rollback_api_router,
)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


async def _posture_regulation_loop():
    while True:
        await asyncio.sleep(3600)
        try:
            import datetime as dt
            hour = dt.datetime.now().hour
            posture_engine.time_based_posture(hour)
            posture_engine.auto_regress()
        except Exception as e:
            logger.warning(f"posture regulation error: {e}")


async def _daily_baseline_loop():
    """Run baseline learning at 01:00 each night."""
    while True:
        import datetime as dt
        now = dt.datetime.now()
        next_run = now.replace(hour=1, minute=0, second=0, microsecond=0)
        if next_run <= now:
            next_run += dt.timedelta(days=1)
        sleep_seconds = (next_run - now).total_seconds()
        await asyncio.sleep(sleep_seconds)

        try:
            yesterday = (dt.datetime.now() - dt.timedelta(days=1)).strftime("%Y-%m-%d")
            profile = baseline_learner.learn_daily(yesterday)
            logger.info(f"baseline learned: {yesterday} total={profile.get('total_commands', 0)}")
        except Exception as e:
            logger.warning(f"baseline learn error: {e}")


async def _proactive_inspection_loop():
    """Run proactive system inspection every INSPECT_INTERVAL seconds."""
    from agent.proactive import INSPECT_INTERVAL
    from routers.ws import broadcast
    from audit.trail import AuditTrail
    while True:
        await asyncio.sleep(INSPECT_INTERVAL)
        try:
            result = proactive_inspector.inspect()
            # Always write inspection result to audit trail for baseline accumulation
            trail = AuditTrail("system:proactive", role="admin")
            trail.chain_close("inspection", {
                "healthy": result["healthy"],
                "disk_pct": result["disk_pct"],
                "mem_pct": result["mem_pct"],
                "critical_count": result["critical_count"],
                "warning_count": result["warning_count"],
                "elapsed_ms": result["elapsed_ms"],
            })
            if not result["healthy"]:
                logger.warning(
                    f"proactive: {result['critical_count']} critical, "
                    f"{result['warning_count']} warnings"
                )
                # Auto-escalate posture on critical findings
                if result["critical_count"] > 0:
                    posture_engine.set_posture("restrictive", "proactive critical alert")
                # Push findings via WebSocket to all connected clients
                for f in result["findings"]:
                    logger.warning(f"  [{f['severity']}] {f['message']}")
                    await broadcast({
                        "type": "alert",
                        "severity": f["severity"],
                        "category": f.get("category", "unknown"),
                        "message": f["message"],
                        "ts": result["ts"],
                    }, actor_user_id="system:proactive", actor_role="admin")
        except Exception as e:
            logger.warning(f"proactive inspection error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.host in ("0.0.0.0", "::"):
        logger.warning(
            "HOST is bound to all interfaces; restrict with firewall/auth and prefer 127.0.0.1 behind a reverse proxy"
        )
    if settings.environment == "production" and not (
        settings.enforce_https or (settings.tls_certfile and settings.tls_keyfile)
    ):
        logger.warning(
            "Production mode is running without HTTPS enforcement; configure TLS_CERTFILE/TLS_KEYFILE or ENFORCE_HTTPS=true"
        )
    register_mcp_tools()
    # Startup auth status (#14)
    from middleware.auth import key_store as _ks
    has_auth = bool(settings.api_key or _ks.list_entries())
    bind_all = settings.host in ("0.0.0.0", "::")
    logger.info("Auth: %s", "configured" if has_auth else "DISABLED — no keys set")
    logger.info("Bind: %s:%s %s", settings.host, settings.port, "⚠️ all interfaces" if bind_all else "✓ localhost")
    if not has_auth and bind_all and settings.environment == "production":
        logger.error("PRODUCTION MODE: No auth keys + binding all interfaces = DANGEROUS")
    task_posture = asyncio.create_task(_posture_regulation_loop())
    task_baseline = asyncio.create_task(_daily_baseline_loop())
    task_inspect = asyncio.create_task(_proactive_inspection_loop())
    yield
    task_posture.cancel()
    task_baseline.cancel()
    task_inspect.cancel()


app = FastAPI(
    title="Kylin OS Security Agent API",
    description="Security-hardened intelligent operations agent for Kylin OS",
    version="0.1.0",
    lifespan=lifespan,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

cors_origins = [o.strip() for o in settings.cors_origins.split(",")]
allow_creds = "*" not in cors_origins  # CORS spec forbids credentials with wildcard
app.add_middleware(CORSMiddleware, allow_origins=cors_origins,
                   allow_credentials=allow_creds, allow_methods=["*"], allow_headers=["*"])
if settings.enforce_https:
    app.add_middleware(HTTPSRedirectMiddleware)
app.add_middleware(BearerTokenMiddleware)

# Serve frontend static files
if os.path.isdir(FRONTEND_DIR):
    app.mount("/src", StaticFiles(directory=os.path.join(FRONTEND_DIR, "src")), name="frontend_src")

    @app.get("/")
    async def index():
        html_path = os.path.join(FRONTEND_DIR, "index.html")
        with open(html_path, "r", encoding="utf-8") as f:
            html = f.read()
        return Response(content=html, media_type="text/html")


# Mount routers
app.include_router(chat_router)
app.include_router(confirm_router)
app.include_router(audit_router)
app.include_router(mcp_router)
app.include_router(system_router)
app.include_router(ws_router)
app.include_router(session_router)
app.include_router(stream_router)
app.include_router(baseline_router)
app.include_router(inspect_router)
app.include_router(rollback_api_router)


@app.exception_handler(Exception)
async def global_exc_handler(request, exc):
    logger.exception(f"Unhandled error: {exc}")
    return Response(content=json.dumps({"error": "Internal server error"}, ensure_ascii=False),
                    status_code=500, media_type="application/json")


if __name__ == "__main__":
    import uvicorn
    ssl_kwargs = {}
    if settings.tls_certfile and settings.tls_keyfile:
        ssl_kwargs = {
            "ssl_certfile": settings.tls_certfile,
            "ssl_keyfile": settings.tls_keyfile,
        }
    uvicorn.run("main:app", host=settings.host, port=settings.port,
                reload=settings.environment != "production", **ssl_kwargs)
