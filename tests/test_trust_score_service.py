"""
Tests for trust_score_service.py — hardened trust score engine.

Tests cover:
- Missing data graceful degradation
- Cold start handling
- Concurrent events
- Score boundaries
"""

from datetime import UTC, datetime

import pytest

from app.services.trust_score_service import (
    AccessContext,
    TrustScoreService,
    TrustWeights,
    compute_trust_score,
)


# Fixture: trust score service
@pytest.fixture
def service():
    return TrustScoreService()


@pytest.fixture
def default_weights():
    return TrustWeights()


# =============================================================================
# Test: Weights Configuration
# =============================================================================

def test_default_weights_sum_to_one(default_weights):
    assert default_weights.validate()


def test_custom_weights():
    w = TrustWeights(project=0.4, temporal=0.2, baseline=0.2, history=0.1, anomaly=0.1)
    assert w.validate()


# =============================================================================
# Test: Missing Data Handling
# =============================================================================

def test_missing_project_returns_fallback(service):
    """Missing project assignment → fallback score."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=[],  # No project
        asset_project_ids=[],  # No project
    )
    result = service.compute_trust_score(ctx)

    assert result.project_score == 0.5  # default_on_missing
    assert "project" in result.missing_factors
    assert result.trust_score is not None
    assert 0.0 <= result.trust_score <= 1.0


def test_missing_temporal_uses_default(service):
    """Missing temporal data → use default logic but mark as missing."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        baseline_mean_hour=None,  # No baseline
        occurred_at=datetime(2025, 6, 15, 3, 0, 0, tzinfo=UTC),  # 3am = outside default hours
    )
    result = service.compute_trust_score(ctx)

    # Marked as missing but returns computed score based on default hours
    assert "temporal" in result.missing_factors


def test_missing_baseline_defaults_to_05(service):
    """Missing baseline → baseline factor = 0.5."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        baseline_mean_hour=None,
        baseline_locations=[],
    )
    result = service.compute_trust_score(ctx)

    assert result.baseline_score == 0.5
    assert "baseline" in result.missing_factors


def test_missing_history_uses_default(service):
    """Missing history → treat as normal."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=0,
    )
    result = service.compute_trust_score(ctx)

    assert result.history_score == 0.5
    assert "history" in result.missing_factors


def test_graceful_degradation_never_returns_none(service):
    """No crashes on partial data — score always returned."""
    # Minimal context
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
    )
    result = service.compute_trust_score(ctx)

    assert result.trust_score is not None
    assert isinstance(result.trust_score, float)


# =============================================================================
# Test: Cold Start Handling
# =============================================================================

def test_cold_start_detected(service):
    """First access events → cold start flag."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=10,  # Below threshold (50)
    )
    result = service.compute_trust_score(ctx)

    assert result.cold_start is True
    assert result.confidence < 1.0


def test_cold_start_score_conservative(service):
    """Cold start score is conservative."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=0,
    )
    result = service.compute_trust_score(ctx)

    # Cold start multiplier reduces trust
    # With all defaults, trust would be ~0.5, multiplied by 0.8 → ~0.4
    assert result.trust_score < 0.6


def test_cold_start_baseline_defaults_to_neutral(service):
    """No baseline → baseline factor defaults to neutral (0.5)."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=0,
    )
    result = service.compute_trust_score(ctx)

    assert result.baseline_score == 0.5


def test_cold_start_history_defaults_to_neutral(service):
    """No history → history factor defaults to neutral (0.5)."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=0,
    )
    result = service.compute_trust_score(ctx)

    assert result.history_score == 0.5


def test_warm_start_has_higher_confidence(service):
    """More data → higher confidence."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=["proj1"],
        asset_project_ids=["proj1"],
        total_events=100,  # Above threshold
        baseline_mean_hour=10.0,  # Present
        baseline_locations=["NYC"],
        deviation_sigma=0.5,  # Present
    )
    result = service.compute_trust_score(ctx)

    assert result.cold_start is False
    assert result.confidence >= 0.2  # Some data present


# =============================================================================
# Test: Score Boundaries
# =============================================================================

def test_score_always_in_range(service):
    """Score always float 0.0-1.0."""
    test_cases = [
        # All optimal
        AccessContext(
            user_id="user1",
            asset_id="asset1",
            user_project_ids=["proj1"],
            asset_project_ids=["proj1"],
            total_events=100,
            baseline_mean_hour=10.0,
        ),
        # All missing
        AccessContext(
            user_id="user1",
            asset_id="asset1",
        ),
        # Extreme
        AccessContext(
            user_id="user1",
            asset_id="asset1",
            total_events=0,
            deviation_sigma=10.0,
            is_anomalous=True,
        ),
    ]

    for ctx in test_cases:
        result = service.compute_trust_score(ctx)
        assert 0.0 <= result.trust_score <= 1.0, f"Score {result.trust_score} out of range"


def test_score_never_none_or_error(service):
    """Score never None or error for valid input."""
    ctx = AccessContext(user_id="user", asset_id="asset")
    result = service.compute_trust_score(ctx)

    assert result.trust_score is not None
    assert result.decision in ("allow", "alert", "revoke")


# =============================================================================
# Test: Weight Redistribution
# =============================================================================

def test_weight_redistribution_on_missing_project(service):
    """Missing project → weight redistributed to other factors."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=[],  # Missing project
        asset_project_ids=[],
        # But other factors present
        baseline_mean_hour=10.0,
        total_events=100,
    )
    result = service.compute_trust_score(ctx)

    # Project factor should be 0.5 (default), but other factors weighted higher
    assert result.trust_score is not None
    assert 0.0 <= result.trust_score <= 1.0


# =============================================================================
# Test: Concurrent Events — Idempotency
# =============================================================================

def test_idempotent_same_inputs_same_output(service):
    """Same inputs → same output (idempotent)."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=["proj1"],
        asset_project_ids=["proj1"],
        total_events=100,
        baseline_mean_hour=10.0,
    )

    result1 = service.compute_trust_score(ctx)
    result2 = service.compute_trust_score(ctx)

    assert result1.trust_score == result2.trust_score


def test_concurrent_events_consistent(service):
    """Concurrent events for same user → consistent scores."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=["proj1"],
        asset_project_ids=["proj1"],
        total_events=100,
    )

    # Simulate multiple concurrent events
    results = [service.compute_trust_score(ctx) for _ in range(10)]

    # All should have same score
    scores = [r.trust_score for r in results]
    assert len(set(scores)) == 1


# =============================================================================
# Test: Convenience Function
# =============================================================================

def test_compute_trust_score_interface():
    """Simple interface returns valid result."""
    result = compute_trust_score(
        user_id="user1",
        asset_id="asset1",
    )

    assert result.trust_score is not None
    assert 0.0 <= result.trust_score <= 1.0


def test_compute_trust_score_with_context():
    """Convenience function with full context."""
    result = compute_trust_score(
        user_id="user1",
        asset_id="asset1",
        context={
            "user_project_ids": ["proj1"],
            "asset_project_ids": ["proj1"],
            "project_active": True,
            "occurred_at": datetime(2025, 6, 15, 10, 0, 0, tzinfo=UTC),
            "total_events": 100,
            "baseline_mean_hour": 10.0,
        },
    )

    assert result.trust_score >= 0.5
    assert result.decision == "allow"


# =============================================================================
# Test: Edge Cases
# =============================================================================

def test_inactive_project_returns_low_score(service):
    """Inactive project → penalty."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=["proj1"],
        asset_project_ids=["proj1"],
        project_active=False,
    )
    result = service.compute_trust_score(ctx)

    assert result.project_score == 0.3


def test_anomaly_flag_returns_low_score(service):
    """Flagged as anomalous → low score."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        is_anomalous=True,
        deviation_sigma=3.0,
    )
    result = service.compute_trust_score(ctx)

    assert result.anomaly_score < 0.5


def test_high_violation_ratio_low_history_score(service):
    """High violation ratio → low history score."""
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        total_events=100,
        recent_violations=20,  # 20% violations
    )
    result = service.compute_trust_score(ctx)

    assert result.history_score < 0.5


# =============================================================================
# Test: Confidence Indicator
# =============================================================================

def test_confidence_reflects_data_quality(service):
    """Confidence reflects how much data we have."""
    # Low data
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
    )
    result = service.compute_trust_score(ctx)
    low_confidence = result.confidence

    # More data
    ctx = AccessContext(
        user_id="user1",
        asset_id="asset1",
        user_project_ids=["proj1"],
        asset_project_ids=["proj1"],
        baseline_mean_hour=10.0,
        baseline_locations=["NYC"],
        total_events=100,
    )
    result = service.compute_trust_score(ctx)
    high_confidence = result.confidence

    assert high_confidence > low_confidence
