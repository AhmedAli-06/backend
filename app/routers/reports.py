import csv
import io
import json
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.access import AccessEvent, AccessSession
from app.models.alert import Alert
from app.models.auth import AuthUser
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


def _parse_date(value: str | None, default_days: int = 7):
    if value:
        return datetime.fromisoformat(value)
    return datetime.now(UTC) - timedelta(days=default_days)


@router.get("/events/csv")
async def export_events_csv(
    hours: int = Query(24, le=168),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    result = await db.execute(
        select(AccessEvent)
        .where(AccessEvent.tenant_id == current_user.tenant_id, AccessEvent.occurred_at >= cutoff)
        .limit(10000)
    )
    events = result.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "event_type", "occurred_at", "trust_score", "decision", "decision_reason"])
    for e in events:
        writer.writerow([str(e.id), e.event_type, e.occurred_at.isoformat(), e.trust_score, e.decision, e.decision_reason])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=access_events_{cutoff.date().isoformat()}.csv"},
    )


@router.get("/events/json")
async def export_events_json(
    hours: int = Query(24, le=168),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    cutoff = datetime.now(UTC) - timedelta(hours=hours)
    result = await db.execute(
        select(AccessEvent)
        .where(AccessEvent.tenant_id == current_user.tenant_id, AccessEvent.occurred_at >= cutoff)
        .limit(10000)
    )
    events = result.scalars().all()

    data = [
        {
            "id": str(e.id),
            "event_type": e.event_type,
            "occurred_at": e.occurred_at.isoformat(),
            "trust_score": e.trust_score,
            "decision": e.decision,
            "decision_reason": e.decision_reason,
        }
        for e in events
    ]

    return StreamingResponse(
        iter([json.dumps(data, indent=2, default=str)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=access_events.json"},
    )


@router.get("/summary")
async def get_summary(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get summary statistics for the dashboard.

    Returns:
      - total_alerts: Total open alerts
      - red_alerts: Critical severity alerts
      - amber_alerts: Warning severity alerts
      - active_sessions: Currently active sessions
      - denied_today: Access denials today
      - events_today: Total events today
    """
    tenant_id = current_user.tenant_id
    today_start = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)

    # Count alerts by status
    alerts_result = await db.execute(
        select(Alert).where(Alert.tenant_id == tenant_id, Alert.status == "open")
    )
    open_alerts = alerts_result.scalars().all()
    total_alerts = len(open_alerts)
    red_alerts = sum(1 for a in open_alerts if a.severity == "critical")
    amber_alerts = sum(1 for a in open_alerts if a.severity == "warning")

    # Count active sessions
    sessions_result = await db.execute(
        select(AccessSession).where(
            AccessSession.tenant_id == tenant_id,
            AccessSession.status == "active"
        )
    )
    active_sessions = len(sessions_result.scalars().all())

    # Count denied events today
    denied_result = await db.execute(
        select(AccessEvent).where(
            AccessEvent.tenant_id == tenant_id,
            AccessEvent.occurred_at >= today_start,
            AccessEvent.decision.in_(["denied", "revoke"])
        )
    )
    denied_today = len(denied_result.scalars().all())

    # Count total events today
    events_result = await db.execute(
        select(AccessEvent).where(
            AccessEvent.tenant_id == tenant_id,
            AccessEvent.occurred_at >= today_start
        )
    )
    events_today = len(events_result.scalars().all())

    return {
        "total_alerts": total_alerts,
        "red_alerts": red_alerts,
        "amber_alerts": amber_alerts,
        "active_sessions": active_sessions,
        "denied_today": denied_today,
        "events_today": events_today
    }


@router.get("/threat-scores")
async def get_threat_scores(
    limit: int = Query(10, le=100),
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get insider threat scores for all users.

    Returns list of users with highest threat scores, including:
      - user info (id, name, department)
      - threat score (0.0-1.0)
      - contributing factors
      - week start date
    """
    from app.services.insider_threat import get_top_threats

    threats = await get_top_threats(db, current_user.tenant_id, limit)
    return threats
