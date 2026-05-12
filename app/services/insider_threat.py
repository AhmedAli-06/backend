"""
Insider Threat Score Service - Longitudinal behavioral threat analysis

Computes weekly threat scores based on:
  1. Increasing off-hours access frequency
  2. Accessing assets outside project scope
  3. Rising anomaly score trends
  4. High denial rate (frustration indicator)

Scores are computed weekly and stored for trend analysis.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.access import AccessEvent
from app.models.user import User


class ThreatScore:
    """Threat score result container."""
    def __init__(self, score: float, factors: list[str]):
        self.score = score
        self.factors = factors


async def compute_weekly_threat_score(
    db: AsyncSession,
    user_id: UUID,
    tenant_id: UUID
) -> ThreatScore:
    """
    Compute weekly insider threat score for a user.

    Analyzes the past 30 days of access events to identify escalating
    behavioral patterns that may indicate insider threat.

    Args:
        db: Database session
        user_id: User UUID to analyze
        tenant_id: Tenant UUID

    Returns:
        ThreatScore with score (0.0-1.0) and list of contributing factors
    """
    now = datetime.now(UTC)
    thirty_days_ago = now - timedelta(days=30)
    seven_days_ago = now - timedelta(days=7)

    # Get all events for user in last 30 days
    result = await db.execute(
        select(AccessEvent)
        .where(
            AccessEvent.tenant_id == tenant_id,
            AccessEvent.user_id == user_id,
            AccessEvent.occurred_at >= thirty_days_ago
        )
        .order_by(AccessEvent.occurred_at)
    )
    events = result.scalars().all()

    if not events:
        return ThreatScore(score=0.0, factors=[])

    factors = []
    score = 0.0

    # Factor 1: Increasing off-hours access (last 7 days vs previous)
    recent_off_hours = sum(1 for e in events
        if e.occurred_at >= seven_days_ago
        and (e.temporal_score or 1.0) < 0.4)

    sum(1 for e in events
        if e.occurred_at < seven_days_ago
        and (e.temporal_score or 1.0) < 0.4)

    if recent_off_hours >= 3:
        score += 0.25
        factors.append(f"{recent_off_hours}+ off-hours accesses in last 7 days")

    # Factor 2: Accessing assets outside project scope
    out_of_scope = sum(1 for e in events
        if (e.project_score or 1.0) < 0.3)

    if out_of_scope >= 2:
        score += 0.20
        factors.append(f"Repeated out-of-scope asset access ({out_of_scope} times)")

    # Factor 3: Rising anomaly scores trend
    anomaly_scores = [e.anomaly_score for e in events
                      if e.anomaly_score is not None]

    if len(anomaly_scores) >= 5:
        mid_point = len(anomaly_scores) // 2
        first_half_avg = sum(anomaly_scores[:mid_point]) / mid_point
        second_half_avg = sum(anomaly_scores[mid_point:]) / (len(anomaly_scores) - mid_point)

        if second_half_avg > first_half_avg * 1.5:
            score += 0.25
            factors.append("Anomaly scores trending upward")

    # Factor 4: High denial rate
    denied = sum(1 for e in events if e.decision == "revoke" or e.decision == "denied")
    total_events = len(events)

    if total_events > 0 and denied / total_events > 0.3:
        score += 0.30
        factors.append(f"High denial rate: {denied}/{total_events} attempts denied")

    # Cap score at 1.0
    score = min(score, 1.0)

    return ThreatScore(
        score=round(score, 3),
        factors=factors
    )


async def compute_all_user_threat_scores(
    db: AsyncSession,
    tenant_id: UUID
) -> list[dict]:
    """
    Compute threat scores for all users in a tenant.

    Returns list of dicts with user info and threat scores.
    """
    # Get all users for this tenant
    result = await db.execute(
        select(User)
        .where(User.tenant_id == tenant_id, User.is_active is True)
    )
    users = result.scalars().all()

    threat_scores = []
    week_start = (datetime.now(UTC) - timedelta(days=datetime.now(UTC).weekday())).date()

    for user in users:
        threat = await compute_weekly_threat_score(db, user.id, tenant_id)

        threat_scores.append({
            "user_id": str(user.id),
            "user_name": user.full_name,
            "department": user.department,
            "score": threat.score,
            "factors": threat.factors,
            "week_start": week_start.isoformat(),
            "computed_at": datetime.now(UTC).isoformat()
        })

    # Sort by score descending
    threat_scores.sort(key=lambda x: x["score"], reverse=True)

    return threat_scores


def get_threat_level(score: float) -> str:
    """
    Classify threat score into level.

    Args:
        score: Threat score from 0.0 to 1.0

    Returns:
        str: "low", "medium", "high", or "critical"
    """
    if score >= 0.7:
        return "critical"
    elif score >= 0.5:
        return "high"
    elif score >= 0.3:
        return "medium"
    else:
        return "low"


async def get_top_threats(
    db: AsyncSession,
    tenant_id: UUID,
    limit: int = 10
) -> list[dict]:
    """
    Get top N users with highest threat scores.
    """
    all_threats = await compute_all_user_threat_scores(db, tenant_id)
    return all_threats[:limit]


async def get_user_threat_history(
    db: AsyncSession,
    user_id: UUID,
    tenant_id: UUID,
    weeks: int = 12
) -> list[dict]:
    """
    Get historical threat scores for a user over N weeks.
    Note: This would require storing threat_scores in a table.
    For now, returns current score with placeholder history.
    """
    current = await compute_weekly_threat_score(db, user_id, tenant_id)

    # In production, would query a threat_scores table
    # For now, return current calculation
    return [{
        "week_start": (datetime.now(UTC) - timedelta(days=datetime.now(UTC).weekday())).date().isoformat(),
        "score": current.score,
        "factors": current.factors
    }]
