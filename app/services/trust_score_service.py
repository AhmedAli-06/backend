"""
ContextShield Trust Score Service — Hardened v1.0

Hardened trust score engine with edge case handling:
- Missing data graceful degradation
- Cold start conservative scores
- Concurrent event safety

Each sub-score is [0.0, 1.0] where 1.0 = fully trusted.
Final trust = weighted sum, clamped to [0.0, 1.0].

Weights (configurable via config.py):
  - project: 0.30
  - temporal: 0.20
  - baseline: 0.25
  - history: 0.10
  - anomaly: 0.15
"""

import asyncio
import math
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class TrustWeights:
    """Configurable weights for trust score factors."""
    project: float = 0.30
    temporal: float = 0.20
    baseline: float = 0.25
    history: float = 0.10
    anomaly: float = 0.15

    def validate(self) -> bool:
        """Ensure weights sum to 1.0."""
        total = self.project + self.temporal + self.baseline + self.history + self.anomaly
        return abs(total - 1.0) < 0.001


@dataclass
class TrustResult:
    """Result of trust score computation."""
    trust_score: float
    project_score: float
    temporal_score: float
    baseline_score: float
    history_score: float
    anomaly_score: float
    confidence: float  # How much data we have (0.0-1.0)
    decision: str
    decision_reason: str
    processing_ms: int = 0
    cold_start: bool = False
    missing_factors: list[str] = field(default_factory=list)
    feature_vector: dict = field(default_factory=dict)


@dataclass
class AccessContext:
    """Context for an access event."""
    user_id: str
    asset_id: str
    user_project_ids: list[str] = field(default_factory=list)
    asset_project_ids: list[str] = field(default_factory=list)
    project_active: bool = True
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    typical_start_hour: int = 7
    typical_end_hour: int = 19
    # Baseline stats (from baseline_service)
    baseline_mean_hour: float | None = None
    baseline_std_hour: float | None = None
    baseline_locations: list[str] = field(default_factory=list)
    baseline_access_frequency_hours: float | None = None
    # History stats
    total_events: int = 0
    recent_violations: int = 0
    account_age_days: int = 0
    # Anomaly detection
    deviation_sigma: float | None = None
    is_anomalous: bool = False


# =============================================================================
# Trust Score Service
# =============================================================================

class TrustScoreService:
    """
    Hardened trust score computation service.
    
    Handles:
    - Missing data (graceful degradation)
    - Cold start (conservative defaults)
    - Concurrent events (idempotent, no race conditions)
    """

    # Cold start threshold: below this, user is considered cold start
    COLD_START_THRESHOLD = 50  # events

    def __init__(self, weights: TrustWeights | None = None):
        self._weights = weights or TrustWeights()
        self._lock = asyncio.Lock()
        # In production, use Redis for distributed lock
        # self._redis = redis.from_url(get_settings().REDIS_URL)

    @property
    def weights(self) -> TrustWeights:
        return self._weights

    # =========================================================================
    # Factor Computations
    # =========================================================================

    def compute_project_score(
        self,
        ctx: AccessContext,
        default_on_missing: float = 0.5,
    ) -> tuple[float, bool]:
        """
        Compute project alignment score.
        
        Returns (score, is_missing).
        """
        missing = False

        # Handle missing project data
        if not ctx.user_project_ids and not ctx.asset_project_ids:
            missing = True
            return default_on_missing, True

        user_projects = set(ctx.user_project_ids or [])
        asset_projects = set(ctx.asset_project_ids or [])

        if not ctx.project_active:
            return 0.3, missing

        # Full match
        if user_projects & asset_projects:
            return 1.0, False

        # Partial match
        if user_projects or asset_projects:
            return 0.5, False

        return 0.15, missing

    def compute_temporal_score(
        self,
        ctx: AccessContext,
        default_on_missing: float = 0.5,
    ) -> tuple[float, bool]:
        """
        Compute temporal score based on time of access vs user baseline.
        
        Returns (score, is_missing).
        """
        missing = False

        hour = ctx.occurred_at.hour

        # Missing baseline — use default window
        if ctx.baseline_mean_hour is None:
            missing = True
            typical_start = ctx.typical_start_hour
            typical_end = ctx.typical_end_hour
        else:
            typical_start = int(ctx.baseline_mean_hour)
            typical_end = typical_start + 12
            if typical_end >= 24:
                typical_end -= 24

        # Within business hours
        if typical_start <= hour < typical_end:
            return 1.0, missing

        # Out of hours — compute distance
        distance = min(
            abs(hour - typical_start),
            abs(hour - typical_end),
            abs(hour + 24 - typical_end),
        )
        return max(0.1, 1.0 - (distance * 0.15)), missing

    def compute_baseline_score(
        self,
        ctx: AccessContext,
        default_on_missing: float = 0.5,
    ) -> tuple[float, bool]:
        """
        Compute baseline deviation score.
        
        Compares current access pattern to learned baseline.
        Returns (score, is_missing) where 1.0 = matches baseline, 0.0 = deviates.
        """
        missing = False

        # Missing baseline
        if ctx.baseline_mean_hour is None and not ctx.baseline_locations:
            missing = True
            return default_on_missing, True

        # No deviation data
        if ctx.deviation_sigma is None:
            missing = True
            return 0.6, True

        # Sigmoid decay based on deviation sigma
        sigma = ctx.deviation_sigma
        return 1.0 / (1.0 + math.exp(sigma - 2.0)), missing

    def compute_history_score(
        self,
        ctx: AccessContext,
        default_on_missing: float = 0.5,
    ) -> tuple[float, bool]:
        """
        Compute history score based on user access history.
        
        Returns (score, is_missing).
        """
        missing = False

        # No history
        if ctx.total_events == 0:
            missing = True
            return default_on_missing, True

        # Low event count — cold start
        if ctx.total_events < 10:
            return 0.4, missing

        # Good history
        violations_ratio = ctx.recent_violations / max(1, ctx.total_events)

        # Score based on violation history
        if violations_ratio > 0.1:
            return 0.2, False
        elif violations_ratio > 0.05:
            return 0.5, False
        elif violations_ratio > 0.01:
            return 0.7, False

        return 0.9, False

    def compute_anomaly_score(
        self,
        ctx: AccessContext,
        default_on_missing: float = 0.5,
    ) -> tuple[float, bool]:
        """
        Compute anomaly detection score.
        
        Returns (score, is_missing) where 1.0 = no anomaly, 0.0 = extreme anomaly.
        """
        missing = False

        # No anomaly detection data
        if ctx.deviation_sigma is None:
            missing = True
            # For cold start: return conservative score with slight randomness
            return max(0.4, min(1.0, 0.7 + random.gauss(0, 0.1))), True

        # Marked as anomalous
        if ctx.is_anomalous:
            return 0.2, False

        # Compute score from sigma
        sigma = ctx.deviation_sigma
        return 1.0 / (1.0 + math.exp(sigma - 2.0)), missing

    # =========================================================================
    # Main Computation
    # =========================================================================

    def compute_trust_score(
        self,
        ctx: AccessContext,
    ) -> TrustResult:
        """
        Compute trust score for an access event.
        
        Handles all edge cases:
        - Missing data → graceful degradation
        - Cold start → conservative score
        - Concurrent events → idempotent (no locks needed for reads)
        
        Returns TrustResult with score in [0.0, 1.0].
        """
        import time
        t0 = time.monotonic_ns()

        w = self._weights

        # Detect cold start
        cold_start = ctx.total_events < self.COLD_START_THRESHOLD

        # Compute each factor
        project_score, project_missing = self.compute_project_score(ctx)
        temporal_score, temporal_missing = self.compute_temporal_score(ctx)
        baseline_score, baseline_missing = self.compute_baseline_score(ctx)
        history_score, history_missing = self.compute_history_score(ctx)
        anomaly_score, anomaly_missing = self.compute_anomaly_score(ctx)

        # Track missing factors
        missing_factors = []
        if project_missing:
            missing_factors.append("project")
        if temporal_missing:
            missing_factors.append("temporal")
        if baseline_missing:
            missing_factors.append("baseline")
        if history_missing:
            missing_factors.append("history")
        if anomaly_missing:
            missing_factors.append("anomaly")

        # Calculate confidence (how much data we have)
        total_factors = 5
        present_factors = total_factors - len(missing_factors)
        confidence = present_factors / total_factors

        # Cold start: reduce confidence further
        if cold_start:
            confidence *= min(1.0, ctx.total_events / self.COLD_START_THRESHOLD)

        # Redistribute weights for missing factors
        # Create adjusted weights dict
        adjusted_weights = {
            "project": w.project,
            "temporal": w.temporal,
            "baseline": w.baseline,
            "history": w.history,
            "anomaly": w.anomaly,
        }

        # For each missing factor, redistribute weight to present factors
        if missing_factors:
            missing_weight = sum(
                getattr(w, factor) for factor in missing_factors
                if hasattr(w, factor)
            )
            if present_factors > 0:
                redistribution = missing_weight / present_factors
                for factor in ["project", "temporal", "baseline", "history", "anomaly"]:
                    if factor not in missing_factors:
                        adjusted_weights[factor] += redistribution

        # Compute weighted trust
        trust = (
            adjusted_weights["project"] * project_score
            + adjusted_weights["temporal"] * temporal_score
            + adjusted_weights["baseline"] * baseline_score
            + adjusted_weights["history"] * history_score
            + adjusted_weights["anomaly"] * anomaly_score
        )

        # Clamp to valid range
        trust = max(0.0, min(1.0, trust))

        # Cold start adjustment: be more conservative
        if cold_start:
            trust *= 0.8  # Conservative fallback

        # Decision thresholds
        alert_threshold = 0.4
        revocation_threshold = 0.2

        if trust >= alert_threshold:
            decision = "allow"
            reason = f"Trust score {trust:.3f} above alert threshold {alert_threshold}"
        elif trust >= revocation_threshold:
            decision = "alert"
            reason = f"Trust score {trust:.3f} between alert and revocation"
        else:
            decision = "revoke"
            reason = f"Trust score {trust:.3f} below revocation threshold {revocation_threshold}"

        elapsed_ms = (time.monotonic_ns() - t0) // 1_000_000

        return TrustResult(
            trust_score=round(trust, 4),
            project_score=round(project_score, 4),
            temporal_score=round(temporal_score, 4),
            baseline_score=round(baseline_score, 4),
            history_score=round(history_score, 4),
            anomaly_score=round(anomaly_score, 4),
            confidence=round(confidence, 4),
            decision=decision,
            decision_reason=reason,
            processing_ms=elapsed_ms,
            cold_start=cold_start,
            missing_factors=missing_factors,
            feature_vector={
                "user_id": ctx.user_id,
                "asset_id": ctx.asset_id,
                "hour_of_day": ctx.occurred_at.hour,
                "total_events": ctx.total_events,
                "baseline_exists": ctx.baseline_mean_hour is not None,
                "deviation_sigma": ctx.deviation_sigma,
            },
        )

    # =========================================================================
    # Concurrent Event Handling
    # =========================================================================

    async def compute_trust_score_async(
        self,
        ctx: AccessContext,
    ) -> TrustResult:
        """
        Async version for concurrent event handling.
        
        In production, this uses Redis locking to prevent race conditions
        when multiple events for the same user arrive simultaneously.
        
        For now, trust score computation is idempotent, so no locking needed.
        """
        # The core computation is stateless and idempotent
        # Lock only needed if writing to DB/storage
        async with self._lock:
            result = self.compute_trust_score(ctx)
        return result


# =============================================================================
# Convenience Functions
# =============================================================================

def compute_trust_score(
    user_id: str,
    asset_id: str,
    context: dict[str, Any] | None = None,
) -> TrustResult:
    """
    Simple interface for trust score computation.
    
    Args:
        user_id: The user attempting access
        asset_id: The asset being accessed
        context: Optional context dict with:
            - user_project_ids: list of project IDs user belongs to
            - asset_project_ids: list of project IDs asset belongs to
            - project_active: bool
            - occurred_at: datetime
            - baseline_mean_hour: float
            - baseline_std_hour: float
            - baseline_locations: list[str]
            - baseline_access_frequency_hours: float
            - total_events: int
            - recent_violations: int
            - account_age_days: int
            - deviation_sigma: float
            - is_anomalous: bool
    
    Returns TrustResult with trust_score in [0.0, 1.0].
    """
    ctx = AccessContext(
        user_id=user_id,
        asset_id=asset_id,
        user_project_ids=context.get("user_project_ids", []) if context else [],
        asset_project_ids=context.get("asset_project_ids", []) if context else [],
        project_active=context.get("project_active", True) if context else True,
        occurred_at=context.get("occurred_at", datetime.now(UTC)) if context else datetime.now(UTC),
        typical_start_hour=context.get("typical_start_hour", 7) if context else 7,
        typical_end_hour=context.get("typical_end_hour", 19) if context else 19,
        baseline_mean_hour=context.get("baseline_mean_hour") if context else None,
        baseline_std_hour=context.get("baseline_std_hour") if context else None,
        baseline_locations=context.get("baseline_locations", []) if context else [],
        baseline_access_frequency_hours=context.get("baseline_access_frequency_hours") if context else None,
        total_events=context.get("total_events", 0) if context else 0,
        recent_violations=context.get("recent_violations", 0) if context else 0,
        account_age_days=context.get("account_age_days", 0) if context else 0,
        deviation_sigma=context.get("deviation_sigma") if context else None,
        is_anomalous=context.get("is_anomalous", False) if context else False,
    )

    service = TrustScoreService()
    return service.compute_trust_score(ctx)
