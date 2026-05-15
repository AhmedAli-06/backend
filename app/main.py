# pyrefly: ignore [missing-import]
import json
import logging
from contextlib import asynccontextmanager
from enum import Enum

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select

logger = logging.getLogger(__name__)


class ErrorCode(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    RATE_LIMITED = "RATE_LIMITED"

from app.config import get_settings
from app.database import Base, engine
from app.middleware.audit import AuditMiddleware
from app.routers.access import router as access_router
from app.routers.alerts import router as alerts_router
from app.routers.api_keys import router as api_keys_router
from app.routers.assets import router as assets_router
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.events import router as events_router
from app.routers.ml import router as ml_router
from app.routers.reports import router as reports_router
from app.routers.sessions import router as sessions_router
from app.routers.settings import router as settings_router
from app.routers.ws import router as ws_router
from app.services.scheduler import register_weekly_retrain_job


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        async with engine.begin() as conn:
            import app.models  # noqa: F401
            await conn.run_sync(Base.metadata.create_all)
    except Exception as e:
        logger.warning(f"Database init skipped: {e}")

    try:
        from app.database import AsyncSessionLocal
        from app.services.insider_threat import compute_all_user_threat_scores

        async def weekly_threat_job():
            from app.models.tenant import Tenant
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Tenant))
                tenants = result.scalars().all()
                for tenant in tenants:
                    await compute_all_user_threat_scores(db, tenant.id)

        scheduler.add_job(weekly_threat_job, "cron", day_of_week="mon", hour=6, minute=0)
        register_weekly_retrain_job(scheduler)
        scheduler.start()
    except Exception as e:
        logger.warning(f"Scheduler init skipped: {e}")

    yield
    try:
        scheduler.shutdown()
    except Exception:
        pass
    await engine.dispose()

app = FastAPI(
    title="ContextShield API",
    description="Intent-Aware Physical Asset Security Platform",
    version="0.2.0-alpha",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=json.loads(get_settings().CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(AuditMiddleware)

app.include_router(auth_router)
app.include_router(dashboard_router)
app.include_router(assets_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(sessions_router)
app.include_router(settings_router)
app.include_router(api_keys_router)
app.include_router(reports_router)
app.include_router(audit_router)
app.include_router(ws_router)
app.include_router(access_router)
app.include_router(ml_router)


# Global exception handler - catch all unhandled errors and return safe JSON
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"code": "INTERNAL_ERROR", "detail": "An unexpected error occurred"}
    )


# Background scheduler for periodic tasks
scheduler = AsyncIOScheduler()

@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.2.0-alpha", "service": "contextshield"}
