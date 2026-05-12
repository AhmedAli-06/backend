"""
Tests for alert_service.py — alert creation and email notifications.

Tests cover:
- Alert creation
- Email delivery
- Retry logic
- Severity classification
- Alert lifecycle
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from app.models.alert import Alert
from app.services.alert_service import (
    classify_severity,
    create_access_alert,
    create_alert,
    send_alert_email,
    send_alert_email_with_tracking,
)

# =============================================================================
# Test: Severity Classification
# =============================================================================

def test_classify_severity_critical_low_trust():
    """Trust score < 0.2 → critical severity."""
    assert classify_severity(0.1) == "critical"


def test_classify_severity_warning_medium_trust():
    """Trust score 0.2-0.4 → warning severity."""
    assert classify_severity(0.3) == "warning"


def test_classify_severity_warning_high_anomaly():
    """High anomaly score → warning even with good trust score."""
    assert classify_severity(0.5, anomaly_score=0.8) == "warning"


def test_classify_severity_info_normal():
    """Normal trust score, no anomaly → info severity."""
    assert classify_severity(0.6) == "info"


def test_classify_severity_boundary_values():
    """Test boundary values."""
    # Exactly 0.2 is boundary - should be warning
    assert classify_severity(0.2) == "warning"
    # Exactly 0.4 is boundary - should be info
    assert classify_severity(0.4) == "info"


# =============================================================================
# Test: Alert Email Without API Key (Mock)
# =============================================================================

@patch("app.services.alert_service.send_email_with_retry")
def test_send_alert_email_without_config(mock_send_email):
    """Missing ALERT_EMAIL env var → graceful handling."""
    # When ALERT_EMAIL is not set, should handle gracefully
    # The function will print a message and return EmailResult with failure
    with patch.dict("os.environ", {}, clear=True):
        result = send_alert_email_with_tracking(
            title="Test Alert",
            description="Test description",
            trust_score=0.1,
        )
        # Should have attempted (but may fail due to missing config)
        assert result is not None


@patch("app.services.alert_service.send_email_with_retry")
def test_send_alert_email_success(mock_send_email):
    """Email sent successfully returns success."""
    mock_send_email.return_value = MagicMock(
        success=True,
        email_id="test-123",
        sent_at=datetime.now(UTC),
        failure_reason=None,
        attempts=1
    )

    with patch.dict("os.environ", {"ALERT_EMAIL": "test@example.com", "RESEND_API_KEY": "test-key"}):
        result = send_alert_email_with_tracking(
            title="Test Alert",
            description="Test description",
            trust_score=0.1,
            user_name="John Doe",
            user_email="john@example.com",
            asset_name="Server Room",
            recommended_action="Review access"
        )

    assert result is not None
    mock_send_email.assert_called_once()


def test_send_alert_email_legacy():
    """Legacy function returns boolean success."""
    with patch("app.services.alert_service.send_alert_email_with_tracking") as mock_tracking:
        mock_tracking.return_value = MagicMock(success=True)
        result = send_alert_email("Test", "Description", 0.1)
        assert result is True


def test_send_alert_email_legacy_failure():
    """Legacy function returns False on failure."""
    with patch("app.services.alert_service.send_alert_email_with_tracking") as mock_tracking:
        mock_tracking.return_value = MagicMock(success=False)
        result = send_alert_email("Test", "Description", 0.1)
        assert result is False


# =============================================================================
# Test: Create Alert Function
# =============================================================================

@pytest.mark.asyncio
async def test_create_alert_creates_alert_object():
    """Basic alert creation returns alert object."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("app.services.alert_service.send_alert_email_with_tracking") as mock_email:
        mock_email.return_value = MagicMock(
            success=False,
            failure_reason="No API key",
            attempts=1
        )

        alert = create_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            severity="warning",
            alert_type="test_alert",
            title="Test Alert",
            description="Test description",
            trust_score=0.3
        )

        assert isinstance(alert, Alert)
        assert alert.title == "Test Alert"
        assert alert.severity == "warning"
        assert alert.trust_score_at_trigger == 0.3


@pytest.mark.asyncio
async def test_create_alert_sends_email_on_critical():
    """Critical severity sends email notification."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    with patch("app.services.alert_service.send_alert_email_with_tracking") as mock_email:
        mock_email.return_value = MagicMock(
            success=True,
            email_id="email-123",
            sent_at=datetime.now(UTC),
            attempts=1
        )

        alert = create_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            severity="critical",
            alert_type="test_alert",
            title="Critical Alert",
            description="Critical description",
            trust_score=0.1,
            user_name="John Doe",
            user_email="john@example.com"
        )

        mock_email.assert_called_once()


@pytest.mark.asyncio
async def test_create_alert_non_critical_no_email():
    """Non-critical severity skips email."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()

    with patch("app.services.alert_service.send_alert_email_with_tracking") as mock_email:
        alert = create_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            severity="info",
            alert_type="test_alert",
            title="Info Alert",
            description="Info description",
            trust_score=0.6
        )

        mock_email.assert_not_called()


# =============================================================================
# Test: Create Access Alert
# =============================================================================

@pytest.mark.asyncio
async def test_create_access_alert_out_of_project():
    """Access alert detects out-of-project scope."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = MagicMock()

    feature_vector = {
        "project_score": 0.1,  # Low - out of scope
        "temporal_score": 0.8,
        "baseline_score": 0.7,
        "history_score": 0.6,
        "anomaly_score": 0.2
    }

    with patch("app.services.alert_service.send_alert_email_with_tracking"):
        alert = await create_access_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            trust_score=0.3,
            feature_vector=feature_vector,
            user_name="John",
            asset_name="Server"
        )

        assert "out of project scope" in alert.description


@pytest.mark.asyncio
async def test_create_access_alert_off_hours():
    """Access alert detects off-hours access."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    feature_vector = {
        "project_score": 0.8,
        "temporal_score": 0.1,  # Low - off hours
        "baseline_score": 0.7,
        "history_score": 0.6,
        "anomaly_score": 0.2
    }

    with patch("app.services.alert_service.send_alert_email_with_tracking"):
        alert = await create_access_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            trust_score=0.3,
            feature_vector=feature_vector
        )

        assert "off hours access" in alert.description


@pytest.mark.asyncio
async def test_create_access_alert_unusual_behavior():
    """Access alert detects unusual behavior pattern."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = AsyncMock()

    feature_vector = {
        "project_score": 0.8,
        "temporal_score": 0.8,
        "baseline_score": 0.7,
        "history_score": 0.6,
        "anomaly_score": 0.8  # High anomaly
    }

    with patch("app.services.alert_service.send_alert_email_with_tracking"):
        alert = await create_access_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            trust_score=0.3,
            feature_vector=feature_vector
        )

        assert "unusual behaviour pattern" in alert.description


@pytest.mark.asyncio
async def test_create_access_alert_rare_access():
    """Access alert detects rarely accessed asset."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.refresh = MagicMock()

    feature_vector = {
        "project_score": 0.8,
        "temporal_score": 0.8,
        "baseline_score": 0.7,
        "history_score": 0.05,  # Very low - rare access
        "anomaly_score": 0.2
    }

    with patch("app.services.alert_service.send_alert_email_with_tracking"):
        alert = await create_access_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            trust_score=0.3,
            feature_vector=feature_vector
        )

        assert "rarely accesses this asset" in alert.description


# =============================================================================
# Test: Alert Lifecycle States
# =============================================================================

@pytest.mark.asyncio
async def test_alert_status_initial():
    """Alert starts with 'open' status."""
    mock_db = MagicMock()
    mock_db.add = MagicMock()

    with patch("app.services.alert_service.send_alert_email_with_tracking"):
        alert = create_alert(
            db=mock_db,
            tenant_id=uuid4(),
            user_id=uuid4(),
            asset_id=uuid4(),
            session_id=None,
            severity="warning",
            alert_type="test",
            title="Test",
            description="Test",
            trust_score=0.3
        )

        assert alert.status == "open"
