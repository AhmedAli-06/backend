from datetime import UTC, datetime

# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.access import AccessEvent, AccessSession
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.auth import AuthUser
from app.schemas import DashboardStats
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    tid = current_user.tenant_id
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

    total_assets = (await db.execute(
        select(func.count()).select_from(Asset).where(Asset.tenant_id == tid)
    )).scalar() or 0

    active_sessions = (await db.execute(
        select(func.count()).select_from(AccessSession)
        .where(AccessSession.tenant_id == tid, AccessSession.status == "active")
    )).scalar() or 0

    open_alerts = (await db.execute(
        select(func.count()).select_from(Alert)
        .where(Alert.tenant_id == tid, Alert.status == "open")
    )).scalar() or 0

    avg_trust = (await db.execute(
        select(func.avg(AccessEvent.trust_score))
        .where(AccessEvent.tenant_id == tid, AccessEvent.occurred_at >= today_start)
    )).scalar() or 0.0

    events_today = (await db.execute(
        select(func.count()).select_from(AccessEvent)
        .where(AccessEvent.tenant_id == tid, AccessEvent.occurred_at >= today_start)
    )).scalar() or 0

    return DashboardStats(
        total_assets=total_assets,
        active_sessions=active_sessions,
        open_alerts=open_alerts,
        avg_trust_score=round(float(avg_trust), 3),
        events_today=events_today,
    )
