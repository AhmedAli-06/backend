"""
ContextShield Trust Score Engine v0.1

Computes a composite trust score from 5 weighted dimensions:
  1. Identity Score   — credential validity, user status
  2. Temporal Score   — time-of-day vs. baseline patterns
  3. Project Score    — user-asset-project authorization alignment
  4. Role Score       — role-based access level match
  5. Anomaly Score    — deviation from learned behavioral baseline

Each sub-score is [0.0, 1.0] where 1.0 = fully trusted.
Final trust = weighted sum, clamped to [0.0, 1.0].
"""

import math
import random
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class TrustWeights:
    identity: float = 0.25
    temporal: float = 0.20
    project: float = 0.25
    role: float = 0.15
    anomaly: float = 0.15


@dataclass
class TrustResult:
    trust_score: float
    identity_score: float
    temporal_score: float
    project_score: float
    role_score: float
    anomaly_score: float
    decision: str
    decision_reason: str
    processing_ms: int = 0
    feature_vector: dict = field(default_factory=dict)


class TrustScoreEngine:
    """Computes trust scores for access events."""

    def __init__(self, weights: TrustWeights | None = None,
                 alert_threshold: float = 0.4,
                 revocation_threshold: float = 0.2):
        self.weights = weights or TrustWeights()
        self.alert_threshold = alert_threshold
        self.revocation_threshold = revocation_threshold

    def compute_identity_score(
        self,
        credential_active: bool,
        user_active: bool,
        credential_expired: bool = False,
    ) -> float:
        if not user_active:
            return 0.0
        if not credential_active or credential_expired:
            return 0.1
        return 1.0

    def compute_temporal_score(
        self,
        occurred_at: datetime,
        typical_start_hour: int = 7,
        typical_end_hour: int = 19,
    ) -> float:
        hour = occurred_at.hour
        if typical_start_hour <= hour < typical_end_hour:
            return 1.0
        # Gradual decay for off-hours
        distance = min(
            abs(hour - typical_start_hour),
            abs(hour - typical_end_hour),
            abs(hour + 24 - typical_end_hour),
        )
        return max(0.1, 1.0 - (distance * 0.15))

    def compute_project_score(
        self,
        user_on_project: bool,
        asset_on_project: bool,
        project_active: bool = True,
    ) -> float:
        if not project_active:
            return 0.3
        if user_on_project and asset_on_project:
            return 1.0
        if user_on_project or asset_on_project:
            return 0.5
        return 0.15

    def compute_role_score(
        self,
        has_required_role: bool,
        role_level: int = 1,
        required_level: int = 1,
    ) -> float:
        if not has_required_role:
            return 0.1
        if role_level >= required_level:
            return 1.0
        return 0.5

    def compute_anomaly_score(
        self,
        baseline_exists: bool = False,
        deviation_sigma: float = 0.0,
    ) -> float:
        """
        For alpha: mock anomaly detection.
        In production this calls the ML ensemble (Isolation Forest + LSTM).
        Returns inverted score: 1.0 = no anomaly, 0.0 = extreme anomaly.
        """
        if not baseline_exists:
            # No baseline yet — neutral score with slight randomness
            return max(0.4, min(1.0, 0.7 + random.gauss(0, 0.1)))
        # Sigmoid decay based on deviation
        return 1.0 / (1.0 + math.exp(deviation_sigma - 2.0))

    def evaluate(
        self,
        credential_active: bool = True,
        user_active: bool = True,
        credential_expired: bool = False,
        occurred_at: datetime | None = None,
        typical_start_hour: int = 7,
        typical_end_hour: int = 19,
        user_on_project: bool = True,
        asset_on_project: bool = True,
        project_active: bool = True,
        has_required_role: bool = True,
        role_level: int = 1,
        required_level: int = 1,
        baseline_exists: bool = False,
        deviation_sigma: float = 0.0,
    ) -> TrustResult:
        import time
        t0 = time.monotonic_ns()

        if occurred_at is None:
            occurred_at = datetime.now(UTC)

        identity = self.compute_identity_score(credential_active, user_active, credential_expired)
        temporal = self.compute_temporal_score(occurred_at, typical_start_hour, typical_end_hour)
        project = self.compute_project_score(user_on_project, asset_on_project, project_active)
        role = self.compute_role_score(has_required_role, role_level, required_level)
        anomaly = self.compute_anomaly_score(baseline_exists, deviation_sigma)

        w = self.weights
        trust = (
            w.identity * identity
            + w.temporal * temporal
            + w.project * project
            + w.role * role
            + w.anomaly * anomaly
        )
        trust = max(0.0, min(1.0, trust))

        # Decision
        if trust >= self.alert_threshold:
            decision, reason = "allow", "Trust score above threshold"
        elif trust >= self.revocation_threshold:
            decision, reason = "alert", f"Trust score {trust:.3f} below alert threshold {self.alert_threshold}"
        else:
            decision, reason = "revoke", f"Trust score {trust:.3f} below revocation threshold {self.revocation_threshold}"

        elapsed_ms = (time.monotonic_ns() - t0) // 1_000_000

        return TrustResult(
            trust_score=round(trust, 4),
            identity_score=round(identity, 4),
            temporal_score=round(temporal, 4),
            project_score=round(project, 4),
            role_score=round(role, 4),
            anomaly_score=round(anomaly, 4),
            decision=decision,
            decision_reason=reason,
            processing_ms=elapsed_ms,
            feature_vector={
                "credential_active": credential_active,
                "user_active": user_active,
                "hour_of_day": occurred_at.hour,
                "user_on_project": user_on_project,
                "asset_on_project": asset_on_project,
                "has_required_role": has_required_role,
                "baseline_exists": baseline_exists,
                "deviation_sigma": deviation_sigma,
            },
        )
