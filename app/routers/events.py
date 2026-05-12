from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.access import AccessEvent
from app.models.auth import AuthUser
from app.schemas import AccessEventResponse
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/events", tags=["Access Events"])


@router.get("/", response_model=list[AccessEventResponse])
async def list_events(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AccessEvent)
        .where(AccessEvent.tenant_id == current_user.tenant_id)
        .order_by(desc(AccessEvent.occurred_at))
        .limit(limit).offset(offset)
    )
    return result.scalars().all()


@router.get("/recent", response_model=list[AccessEventResponse])
async def recent_events(
    hours: int = Query(24, le=168),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    result = await db.execute(
        select(AccessEvent)
        .where(AccessEvent.tenant_id == current_user.tenant_id, AccessEvent.occurred_at >= cutoff)
        .order_by(desc(AccessEvent.occurred_at))
        .limit(100)
    )
    return result.scalars().all()
