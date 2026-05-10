from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.alert import Alert
from app.models.auth import AuthUser
from app.schemas import AlertResponse, AlertUpdate
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    status: str | None = Query(None),
    limit: int = Query(50, le=200),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(Alert)
        .where(Alert.tenant_id == current_user.tenant_id)
        .options(selectinload(Alert.user), selectinload(Alert.asset))
    )
    if status:
        q = q.where(Alert.status == status)
    q = q.order_by(desc(Alert.triggered_at)).limit(limit)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: UUID,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user.tenant_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Alert not found"})
    return alert


@router.put("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: UUID,
    current_user: AuthUser = Depends(require_role("security_officer")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user.tenant_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Alert not found"})

    alert.status = "acknowledged"
    alert.acknowledged_at = datetime.now(UTC)
    alert.acknowledged_by = current_user.id
    await db.commit()
    await db.refresh(alert)
    return alert


@router.put("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: UUID,
    body: AlertUpdate = AlertUpdate(status="resolved"),
    current_user: AuthUser = Depends(require_role("security_officer")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user.tenant_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Alert not found"})

    alert.status = body.status
    alert.resolved_at = datetime.now(UTC)
    alert.resolved_by = current_user.id
    alert.resolution_notes = body.resolution_notes
    await db.commit()
    await db.refresh(alert)
    return alert


@router.put("/{alert_id}/dismiss", response_model=AlertResponse)
async def dismiss_alert(
    alert_id: UUID,
    current_user: AuthUser = Depends(require_role("security_officer")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id,
            Alert.tenant_id == current_user.tenant_id,
        )
    )
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Alert not found"})

    alert.status = "dismissed"
    alert.resolved_at = datetime.now(UTC)
    alert.resolved_by = current_user.id
    alert.resolution_notes = "Dismissed by security officer"
    await db.commit()
    await db.refresh(alert)
    return alert
