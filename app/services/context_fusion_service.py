"""
Context Fusion Service v1.0

Provides reliable context fusion with graceful degradation when data sources are unavailable.
Wraps the core context fusion logic with error handling, timeouts, and fallback values.

Main function:
  - fuse_context(user_id, asset_id, access_time): Returns context dict with fallback values on errors

Context includes:
  - project_relevance: float (0.0-1.0)
  - temporal_score: float (0.0-1.0)
  - role_match: float (0.0-1.0)
  - schedule_compliance: float (0.0-1.0)
"""

import logging
from asyncio import timeout
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

# Import core context fusion functions
from app.services.context_fusion import get_context

logger = logging.getLogger(__name__)

# Timeout for external data source calls (in seconds)
CONTEXT_TIMEOUT_SECONDS = 2.0

# Fallback values for graceful degradation (neutral - not trusting or suspicious)
FALLBACK_CONTEXT = {
    "project_relevance": 0.5,
    "temporal_score": 0.5,
    "role_match": 0.5,
    "schedule_compliance": 0.5,
    "hour": 12,
    "weekday": 0,
    "typical_hours": [],
    "fallback_used": True
}


async def fuse_context(
    db: AsyncSession,
    user_id: UUID,
    asset_id: UUID,
    tenant_id: UUID,
    access_time: datetime | None = None
) -> dict:
    """
    Fuse context data from multiple sources with graceful degradation.

    Always returns a valid context dict - never returns None or raises unhandled exceptions.
    When data sources are unavailable, returns neutral fallback values (0.5 for all scores).

    Args:
        db: Database session
        user_id: UUID of the user accessing the asset
        asset_id: UUID of the asset being accessed
        tenant_id: UUID of the tenant
        access_time: Optional datetime of when access occurred (defaults to now)

    Returns:
        dict with:
          - project_relevance: float (0.0-1.0)
          - temporal_score: float (0.0-1.0)
          - role_match: float (0.0-1.0)
          - schedule_compliance: float (0.0-1.0)
          - hour: int (0-23)
          - weekday: int (0=Monday, 6=Sunday)
          - typical_hours: list[int]
          - fallback_used: bool (True if any fallback was applied)
    """
    if access_time is None:
        access_time = datetime.now(UTC)

    try:
        # Use timeout to prevent hanging on external calls
        async with timeout(CONTEXT_TIMEOUT_SECONDS):
            context = await get_context(db, user_id, asset_id, tenant_id, access_time)

        # Map context_fusion.py output to the expected schema
        # The core module returns: project_score, temporal_score, baseline_score, history_score
        # We map these to the service's expected output
        result = {
            "project_relevance": context.get("project_score", 0.5),
            "temporal_score": context.get("temporal_score", 0.5),
            "role_match": context.get("baseline_score", 0.5),  # Map baseline to role_match
            "schedule_compliance": context.get("history_score", 0.5),  # Map history to schedule
            "hour": context.get("hour", 12),
            "weekday": context.get("weekday", 0),
            "typical_hours": context.get("typical_hours", []),
            "fallback_used": False
        }

        logger.debug(
            f"Context fusion successful for user={user_id}, asset={asset_id}: "
            f"project={result['project_relevance']}, temporal={result['temporal_score']}"
        )

        return result

    except TimeoutError:
        logger.warning(
            f"Context fusion timeout for user={user_id}, asset={asset_id}, "
            f"using fallback values (timeout={CONTEXT_TIMEOUT_SECONDS}s)"
        )
        return FALLBACK_CONTEXT.copy()

    except Exception as e:
        # Catch all other exceptions (database errors, connection issues, etc.)
        logger.warning(
            f"Context fusion: data source unavailable for user={user_id}, asset={asset_id}, "
            f"error={type(e).__name__}: {str(e)}, using fallback values"
        )

        # Track fallback usage in metrics (log for monitoring)
        logger.info(
            f"Context fusion fallback metrics: "
            f"user={user_id}, asset={asset_id}, error_type={type(e).__name__}"
        )

        return FALLBACK_CONTEXT.copy()


async def fuse_context_simple(
    user_id: UUID,
    asset_id: UUID,
    access_time: datetime | None = None
) -> dict:
    """
    Simple synchronous-style interface for context fusion.
    Returns fallback values - used when no database session is available.

    This is a convenience function for cases where database access is not available.
    """
    logger.warning(
        f"Context fusion called without db session for user={user_id}, asset={asset_id}, "
        "using fallback values"
    )

    if access_time is None:
        access_time = datetime.now(UTC)

    result = FALLBACK_CONTEXT.copy()
    result["hour"] = access_time.hour
    result["weekday"] = access_time.weekday()

    return result
