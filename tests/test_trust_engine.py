from datetime import UTC, datetime

from app.services.trust_engine import TrustScoreEngine, TrustWeights

engine = TrustScoreEngine()

def test_identity_score_full_trust():
    assert engine.compute_identity_score(True, True, False) == 1.0

def test_identity_score_inactive_user():
    assert engine.compute_identity_score(True, False, False) == 0.0

def test_identity_score_expired_credential():
    assert engine.compute_identity_score(False, True, True) == 0.1

def test_temporal_score_business_hours():
    dt = datetime(2025, 6, 15, 10, 0, 0, tzinfo=UTC)
    assert engine.compute_temporal_score(dt, 7, 19) == 1.0

def test_temporal_score_off_hours():
    dt = datetime(2025, 6, 15, 3, 0, 0, tzinfo=UTC)
    score = engine.compute_temporal_score(dt, 7, 19)
    assert 0.0 < score < 1.0

def test_project_score_full_match():
    assert engine.compute_project_score(True, True, True) == 1.0

def test_project_score_no_match():
    assert engine.compute_project_score(False, False, True) == 0.15

def test_project_score_partial_match():
    assert engine.compute_project_score(True, False, True) == 0.5

def test_project_score_inactive_project():
    assert engine.compute_project_score(True, True, False) == 0.3

def test_role_score_has_role():
    assert engine.compute_role_score(True, 3, 2) == 1.0

def test_role_score_insufficient_level():
    assert engine.compute_role_score(True, 1, 3) == 0.5

def test_role_score_no_role():
    assert engine.compute_role_score(False, 1, 1) == 0.1

def test_anomaly_score_no_baseline():
    score = engine.compute_anomaly_score(False)
    assert 0.4 <= score <= 1.0

def test_anomaly_score_high_deviation():
    score = engine.compute_anomaly_score(True, 5.0)
    assert score < 0.5

def test_evaluate_full_trust():
    result = engine.evaluate(
        credential_active=True, user_active=True,
        occurred_at=datetime(2025, 6, 15, 10, 0, 0, tzinfo=UTC),
        typical_start_hour=7, typical_end_hour=19,
        user_on_project=True, asset_on_project=True, project_active=True,
        has_required_role=True, role_level=3, required_level=2,
        baseline_exists=False,
    )
    assert result.trust_score > 0.7
    assert result.decision == "allow"
    assert result.processing_ms >= 0

def test_evaluate_revocation():
    result = engine.evaluate(
        credential_active=False, user_active=True,
        occurred_at=datetime(2025, 6, 15, 3, 0, 0, tzinfo=UTC),
        user_on_project=False, asset_on_project=False, project_active=False,
        has_required_role=False, role_level=0, required_level=5,
        baseline_exists=True, deviation_sigma=8.0,
    )
    assert result.trust_score < 0.2
    assert result.decision == "revoke"

def test_evaluate_alert():
    result = engine.evaluate(
        credential_active=True, user_active=True,
        occurred_at=datetime(2025, 6, 15, 22, 0, 0, tzinfo=UTC),
        user_on_project=True, asset_on_project=False, project_active=True,
        has_required_role=True, role_level=1, required_level=1,
        baseline_exists=False,
    )
    assert result.decision in ("allow", "alert")

def test_custom_weights():
    w = TrustWeights(identity=0.5, temporal=0.1, project=0.2, role=0.1, anomaly=0.1)
    e = TrustScoreEngine(weights=w)
    result = e.evaluate(credential_active=True, user_active=True)
    assert 0 < result.trust_score <= 1.0

def test_alert_threshold():
    e = TrustScoreEngine(alert_threshold=0.8, revocation_threshold=0.3)
    result = e.evaluate(
        credential_active=True, user_active=True,
        occurred_at=datetime(2025, 6, 15, 22, 0, 0, tzinfo=UTC),
        user_on_project=False, asset_on_project=False,
        has_required_role=False,
    )
    if result.trust_score < 0.8 and result.trust_score >= 0.3:
        assert result.decision == "alert"
