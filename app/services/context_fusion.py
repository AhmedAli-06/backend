"""
Context Fusion Engine v1.0

Computes contextual factors for trust scoring:
  1. Project Score — user-asset-project authorization alignment
  2. Temporal Score — time-of-day vs. typical working hours
  3. Baseline Score — user-asset historical pattern matching
  4. History Score — recent access frequency

Each sub-score is [0.0, 1.0] where 1.0 = fully trusted.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.access import AccessEvent
from app.models.asset import AssetProject, Project, ProjectMember
from app.services.baseline_service import get_baseline_stats


async def get_context(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    tenant_id: UUID,
    occurred_at: datetime | None = None
) -> dict:
    """
    Compute all context factors for a user-asset access attempt.

    Returns dict with:
      - project_score: float (0.0-1.0)
      - temporal_score: float (0.0-1.0)
      - baseline_score: float (0.0-1.0)
      - history_score: float (0.0-1.0)
      - hour: int
      - weekday: int (0=Monday, 6=Sunday)
      - typical_hours: list[int]
    """
    if occurred_at is None:
        occurred_at = datetime.now(UTC)

    hour = occurred_at.hour
    weekday = occurred_at.weekday()  # 0=Monday, 6=Sunday

    project_score = await compute_project_score(db, user_id, asset_id, tenant_id)
    temporal_score = compute_temporal_score(occurred_at)
    baseline_score, typical_hours = await compute_baseline_score(db, user_id, asset_id, hour)
    history_score = await compute_history_score(db, user_id, asset_id, tenant_id)

    return {
        "project_score": project_score,
        "temporal_score": temporal_score,
        "baseline_score": baseline_score,
        "history_score": history_score,
        "hour": hour,
        "weekday": weekday,
        "typical_hours": typical_hours
    }


async def compute_project_score(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    tenant_id: UUID
) -> float:
    """
    Determine if user is authorized for this asset via active projects.

    Returns:
      - 1.0: user on active project AND asset belongs to that project
      - 0.3: user on project but asset not in project scope (project ended)
      - 0.15: no project association
    """
    # Get user's active projects
    result = await db.execute(
        select(ProjectMember.project_id)
        .join(Project, ProjectMember.project_id == Project.id)
        .where(
            ProjectMember.user_id == user_id,
            Project.tenant_id == tenant_id,
            Project.status == "active"
        )
    )
    user_project_ids = [row[0] for row in result.fetchall()]

    if not user_project_ids:
        return 0.15

    # Check if asset belongs to any of user's active projects
    asset_projects_result = await db.execute(
        select(AssetProject.project_id)
        .where(
            AssetProject.asset_id == asset_id,
            AssetProject.project_id.in_(user_project_ids)
        )
    )
    asset_in_user_projects = len(asset_projects_result.fetchall()) > 0

    if asset_in_user_projects:
        return 1.0

    # Check if asset belongs to any active project (user might not be on it)
    any_active_result = await db.execute(
        select(Project.id)
        .where(
            Project.id.in_(user_project_ids),
            Project.status == "active"
        )
    )
    if any_active_result.fetchall():
        return 0.3  # User on active project but asset not in scope

    return 0.15


def compute_temporal_score(occurred_at: datetime) -> float:
    """
    Determine if access is during typical working hours.

    Returns:
      - 1.0: Business hours (Mon-Fri, 8am-6pm)
      - 0.6: Extended hours (6am-8pm)
      - 0.1: Off hours (suspicious)
    """
    hour = occurred_at.hour
    weekday = occurred_at.weekday()

    if 8 <= hour <= 18 and weekday < 5:
        return 1.0
    elif 6 <= hour <= 20:
        return 0.6
    else:
        return 0.1


async def compute_baseline_score(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    current_hour: int
) -> tuple[float, list[int]]:
    """
    Compare current access against user's historical baseline for this asset.

    Returns:
      - baseline_score: float (0.0-1.0)
      - typical_hours: list of hours when user typically accesses this asset
    """
    baseline = await get_baseline_stats(db, user_id, asset_id)

    if baseline is None or not baseline.get("typical_hours"):
        return 0.5, []

    typical_hours = baseline.get("typical_hours", [])

    if current_hour in typical_hours:
        return 1.0, typical_hours
    else:
        return 0.2, typical_hours


async def compute_history_score(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    tenant_id: UUID
) -> float:
    """
    Calculate how frequently user has accessed this asset in last 30 days.

    Returns:
      - Score from 0.0 to 1.0 based on access frequency
      - 1.0 = frequent access (10+ times)
      - 0.1 = no recent access
    """
    thirty_days_ago = datetime.now(UTC) - timedelta(days=30)

    result = await db.execute(
        select(AccessEvent.id)
        .where(
            AccessEvent.tenant_id == tenant_id,
            AccessEvent.user_id == user_id,
            AccessEvent.asset_id == asset_id,
            AccessEvent.occurred_at >= thirty_days_ago
        )
    )
    access_count = len(result.fetchall())

    return min(access_count / 10.0, 1.0)


async def get_user_asset_context(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    tenant_id: UUID,
    occurred_at: datetime | None = None
) -> dict:
    """
    Main entry point - returns full context for trust scoring.
    """
    return await get_context(db, user_id, asset_id, tenant_id, occurred_at)
