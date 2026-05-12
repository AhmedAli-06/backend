"""
Baseline Service - Manages user-asset access baselines

Stores and retrieves baseline statistics for behavioral anomaly detection.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.access import AccessEvent

MODEL_DIR = "ml/models"


async def get_baseline_stats(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID
) -> dict | None:
    """
    Compute and return baseline statistics for a user-asset pair.

    Returns dict with:
      - avg_session_duration_mins: float
      - typical_hours: list[int] (hours of day when access typically occurs)
      - avg_weekly_frequency: float
      - last_trained_at: datetime
      - model_path: str (path to trained ML model)
    """
    # Get last 30 days of access events for this user-asset pair
    thirty_days_ago = datetime.now(UTC) - timedelta(days=30)

    result = await db.execute(
        select(AccessEvent)
        .where(
            AccessEvent.user_id == user_id,
            AccessEvent.asset_id == asset_id,
            AccessEvent.occurred_at >= thirty_days_ago
        )
        .order_by(AccessEvent.occurred_at)
    )
    events = result.scalars().all()

    if len(events) < 5:
        return None

    # Calculate typical hours (hour of day for each access)
    hour_counts = {}
    for event in events:
        hour = event.occurred_at.hour
        hour_counts[hour] = hour_counts.get(hour, 0) + 1

    # Get hours that account for >10% of accesses
    total_accesses = len(events)
    typical_hours = [h for h, count in hour_counts.items() if count / total_accesses > 0.1]

    # Calculate weekly frequency
    days_span = (events[-1].occurred_at - events[0].occurred_at).days + 1
    weeks = max(days_span / 7.0, 1.0)
    avg_weekly_frequency = len(events) / weeks

    # Calculate average session duration (estimate from trust score stability)
    # For now, estimate based on access pattern
    avg_session_duration_mins = 30.0  # Default 30 min

    return {
        "avg_session_duration_mins": avg_session_duration_mins,
        "typical_hours": typical_hours,
        "avg_weekly_frequency": round(avg_weekly_frequency, 2),
        "last_trained_at": datetime.now(UTC).isoformat(),
        "model_path": f"{MODEL_DIR}/{user_id}_{asset_id}.pkl"
    }


async def update_baseline_stats(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID
) -> dict:
    """
    Recompute and store baseline statistics.
    Called periodically or after sufficient new events.
    """
    stats = await get_baseline_stats(db, user_id, asset_id)

    if stats is None:
        return {
            "status": "insufficient_data",
            "message": "Need at least 5 access events to establish baseline"
        }

    return {
        "status": "updated",
        "user_id": str(user_id),
        "asset_id": str(asset_id),
        "typical_hours": stats["typical_hours"],
        "avg_weekly_frequency": stats["avg_weekly_frequency"]
    }


def get_model_path(user_id: UUID, asset_id: UUID) -> str:
    """Get the path to the trained model for this user-asset pair."""
    return f"{MODEL_DIR}/{user_id}_{asset_id}.pkl"
