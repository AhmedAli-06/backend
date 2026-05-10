"""
Access Control Router - Badge Swipe Processing

Core endpoint: POST /api/v1/access/swipe
Processes badge swipes and computes trust scores using:
  - Context fusion (project, temporal, baseline, history)
  - Anomaly detection (Isolation Forest)
  - Ghost access detection (simultaneous sessions, impossible travel)
  - Alert creation and email notification
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.access import AccessEvent, AccessSession
from app.models.asset import Asset
from app.models.auth import AuthUser
from app.models.user import Credential, User
from app.routers.ws import manager
from app.security import get_current_user
from app.services.alert_service import create_access_alert
from app.services.anomaly_detector import get_anomaly_score
from app.services.context_fusion import get_user_asset_context
from app.services.ghost_access import check_ghost_access

router = APIRouter(prefix="/api/v1/access", tags=["Access Control"])


class SwipeRequest(BaseModel):
    """Request body for badge swipe."""
    credential_value: str  # Badge RFID value
    asset_id: str  # UUID of asset being accessed


class SwipeResponse(BaseModel):
    """Response for badge swipe."""
    decision: str  # "granted", "advisory", "denied"
    reason: str | None = None
    trust_score: float
    anomaly_score: float
    feature_vector: dict
    session_id: str | None = None
    ghost_detected: bool = False
    ghost_reason: str | None = None
    ghost_detection_data: dict | None = None  # Enhanced with location/speed/IP details


@router.post("/swipe", response_model=SwipeResponse)
async def process_badge_swipe(
    swipe: SwipeRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Process a badge swipe at an asset.

    This is the main endpoint for physical access control.
    It resolves the credential to a user, checks for ghost access,
    computes trust score using context + anomaly detection,
    creates a session if granted, logs the event, and triggers alerts.
    """
    tenant_id = current_user.tenant_id

    # Validate asset exists
    try:
        asset_uuid = UUID(swipe.asset_id)
    except ValueError:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "detail": "Invalid asset_id format"})

    asset_result = await db.execute(
        select(Asset).where(Asset.id == asset_uuid, Asset.tenant_id == tenant_id)
    )
    asset = asset_result.scalar_one_or_none()

    if not asset:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Asset not found"})

    # Resolve credential to user (single JOIN query, no N+1)
    credential_result = await db.execute(
        select(Credential)
        .join(User, Credential.user_id == User.id)
        .options(selectinload(Credential.user))
        .where(
            Credential.credential_value == swipe.credential_value,
            Credential.is_active is True,
            User.is_active is True
        )
    )
    credential = credential_result.scalar_one_or_none()

    if not credential:
        return SwipeResponse(
            decision="denied",
            reason="invalid_credential",
            trust_score=0.0,
            anomaly_score=0.0,
            feature_vector={},
            ghost_detected=False
        )

    user = credential.user  # Already loaded via selectinload — no extra query
    if not user or user.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "detail": "User not authorized for this tenant"})

    user_id = user.id
    occurred_at = datetime.now(UTC)

    # Step 1: Ghost Access Detection (enhanced with configurable thresholds)
    ghost_result = await check_ghost_access(
        db, user_id, asset_uuid, swipe.credential_value, tenant_id
    )
    ghost_penalty = ghost_result.get("penalty", 0.0)
    ghost_detected = ghost_result.get("ghost_detected", False)
    ghost_reason = ghost_result.get("reason")

    # Get detection data for alert enrichment
    detection_data = ghost_result.get("detection_data", {})

    # Step 2: Get Context (project, temporal, baseline, history scores)
    context = await get_user_asset_context(
        db, user_id, asset_uuid, tenant_id, occurred_at
    )

    # Step 3: Anomaly Detection (ML)
    anomaly_score = get_anomaly_score(
        user_id, asset_uuid, context, session_history=None
    )

    # Step 4: Compute Trust Score (weighted combination)
    trust_score = compute_trust_score(context, anomaly_score)

    # Apply ghost penalty
    trust_score = max(0.0, min(1.0, trust_score - ghost_penalty))

    # Step 5: Make Decision
    if ghost_detected:
        decision = "denied"
        decision_reason = ghost_result.get("detail", "Ghost access detected")
    elif trust_score >= 0.7:
        decision = "granted"
        decision_reason = "Trust score above threshold"
    elif trust_score >= 0.4:
        decision = "advisory"
        decision_reason = f"Trust score {trust_score:.3f} below granted threshold"
    else:
        decision = "denied"
        decision_reason = f"Trust score {trust_score:.3f} below advisory threshold"

    # Step 6: Create session if granted or advisory
    session_id = None
    if decision in ["granted", "advisory"]:
        session = AccessSession(
            tenant_id=tenant_id,
            user_id=user_id,
            asset_id=asset_uuid,
            started_at=occurred_at,
            status="active",
            avg_trust_score=trust_score,
            min_trust_score=trust_score
        )
        db.add(session)
        await db.flush()
        session_id = str(session.id)

    # Step 7: Log access event
    event = AccessEvent(
        tenant_id=tenant_id,
        user_id=user_id,
        asset_id=asset_uuid,
        credential_id=credential.id,
        session_id=UUID(session_id) if session_id else None,
        event_type="badge_swipe",
        event_source="rfid_reader",
        occurred_at=occurred_at,
        trust_score=trust_score,
        project_score=context.get("project_score"),
        temporal_score=context.get("temporal_score"),
        baseline_score=context.get("baseline_score"),
        history_score=context.get("history_score"),
        anomaly_score=anomaly_score,
        decision=decision,
        decision_reason=decision_reason,
        feature_vector={
            "project_score": context.get("project_score"),
            "temporal_score": context.get("temporal_score"),
            "baseline_score": context.get("baseline_score"),
            "history_score": context.get("history_score"),
            "anomaly_score": anomaly_score
        }
    )
    db.add(event)

    # Step 8: Create alert if trust score is low OR ghost detected
    if ghost_detected:
        from app.services.ghost_access import create_ghost_alert
        await create_ghost_alert(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            asset_id=asset_uuid,
            ghost_result=ghost_result,
            session_id=UUID(session_id) if session_id else None,
            trust_score=trust_score
        )
    elif trust_score < 0.7:
        await create_access_alert(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            asset_id=asset_uuid,
            session_id=UUID(session_id) if session_id else None,
            trust_score=trust_score,
            feature_vector={
                "project_score": context.get("project_score"),
                "temporal_score": context.get("temporal_score"),
                "baseline_score": context.get("baseline_score"),
                "history_score": context.get("history_score"),
                "anomaly_score": anomaly_score
            }
        )

    # Commit all changes
    await db.commit()

    # Step 9: Broadcast to WebSocket clients
    await manager.broadcast({
        "type": "new_access_event",
        "user": user.full_name,
        "asset": asset.name,
        "asset_id": str(asset.id),
        "trust_score": trust_score,
        "decision": decision,
        "timestamp": occurred_at.isoformat()
    })

    return SwipeResponse(
        decision=decision,
        reason=decision_reason,
        trust_score=round(trust_score, 3),
        anomaly_score=anomaly_score,
        feature_vector={
            "project_score": round(context.get("project_score", 0), 3),
            "temporal_score": round(context.get("temporal_score", 0), 3),
            "baseline_score": round(context.get("baseline_score", 0), 3),
            "history_score": round(context.get("history_score", 0), 3),
            "anomaly_score": anomaly_score
        },
        session_id=session_id,
        ghost_detected=ghost_detected,
        ghost_reason=ghost_reason,
        ghost_detection_data=detection_data if ghost_detected else None
    )


def compute_trust_score(context: dict, anomaly_score: float) -> float:
    """
    Compute trust score from context factors and anomaly score.

    Weights (from Final-Plan.md):
      - project: 0.30
      - temporal: 0.20
      - baseline: 0.25
      - history: 0.10
      - anomaly: 0.15 (subtracted)
    """
    weights = {
        "project": 0.30,
        "temporal": 0.20,
        "baseline": 0.25,
        "history": 0.10,
        "anomaly": 0.15
    }

    trust = (
        weights["project"] * context.get("project_score", 0.5) +
        weights["temporal"] * context.get("temporal_score", 0.5) +
        weights["baseline"] * context.get("baseline_score", 0.5) +
        weights["history"] * context.get("history_score", 0.5) -
        weights["anomaly"] * anomaly_score
    )

    return max(0.0, min(1.0, trust))


@router.get("/simulate-swipe/{asset_id}")
async def simulate_swipe(
    asset_id: str,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Simulate a badge swipe for testing/demo purposes.
    Uses the current authenticated user's first active credential.
    """
    tenant_id = current_user.tenant_id

    # Get user's first active credential
    cred_result = await db.execute(
        select(Credential)
        .where(
            Credential.tenant_id == tenant_id,
            Credential.is_active is True
        )
        .limit(1)
    )
    credential = cred_result.scalar_one_or_none()

    if not credential:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "No active credentials found"})

    swipe_request = SwipeRequest(
        credential_value=credential.credential_value,
        asset_id=asset_id
    )

    return await process_badge_swipe(swipe_request, current_user, db)
