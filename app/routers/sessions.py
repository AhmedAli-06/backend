from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import selectinload, noload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.access import AccessSession
from app.models.auth import AuthUser
from app.schemas import RevokeResponse, SessionResponse
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/v1/sessions", tags=["Sessions"])


@router.get("/", response_model=list[SessionResponse])
async def list_sessions(
    status: str | None = None,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = (
        select(AccessSession)
        .where(AccessSession.tenant_id == current_user.tenant_id)
        .options(
            selectinload(AccessSession.user),
            selectinload(AccessSession.asset),
            noload(AccessSession.events),  # Events not needed for list view
        )
    )
    if status:
        q = q.where(AccessSession.status == status)
    q = q.limit(100)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/active", response_model=list[SessionResponse])
async def active_sessions(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AccessSession)
        .where(AccessSession.tenant_id == current_user.tenant_id, AccessSession.status == "active")
        .limit(100)
    )
    return result.scalars().all()


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: UUID,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AccessSession).where(
            AccessSession.id == session_id,
            AccessSession.tenant_id == current_user.tenant_id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Session not found"})
    return session


@router.post("/{session_id}/revoke", response_model=RevokeResponse)
async def revoke_session(
    session_id: UUID,
    reason: str = "Manual revocation by admin",
    current_user: AuthUser = Depends(require_role("security_officer")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AccessSession).where(
            AccessSession.id == session_id,
            AccessSession.tenant_id == current_user.tenant_id,
        )
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Session not found"})
    if session.status != "active":
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "detail": "Session is not active"})

    now = datetime.now(UTC)
    session.status = "revoked"
    session.ended_at = now
    if session.started_at:
        session.duration_seconds = int((now - session.started_at).total_seconds())
    session.revocation_reason = reason
    await db.commit()
    await db.refresh(session)

    return RevokeResponse(
        session_id=session.id,
        status="revoked",
        revoked_at=now,
        reason=reason,
    )
