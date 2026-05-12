"""
Tests for email_service.py — email delivery with retry logic.

Tests cover:
- Send success
- Retry on failure
- Exponential backoff
- Max retries respected
- Result tracking
"""

import pytest
import os
from unittest.mock import patch, MagicMock

from app.services.email_service import (
    send_email_with_retry,
    send_email,
    EmailResult,
)


# =============================================================================
# Test: Missing Configuration
# =============================================================================

def test_send_email_no_api_key():
    """Missing API key returns failure result."""
    # Clear any env vars that might exist
    with patch.dict("os.environ", {}, clear=True):
        result = send_email_with_retry(
            to="test@example.com",
            subject="Test",
            html_body="<p>Test</p>"
        )

        assert result.success is False
        assert result.failure_reason == "RESEND_API_KEY not configured"
        assert result.attempts == 1


def test_send_email_resend_not_installed():
    """Resend package not installed → failure result."""
    with patch.dict("os.environ", {"RESEND_API_KEY": "test-key"}):
        with patch("builtins.__import__") as mock_import:
            # Make import of resend raise ImportError
            def import_side_effect(name, *args, **kwargs):
                if name == "resend":
                    raise ImportError("No module named 'resend'")
                return __import__(name, *args, **kwargs)

            mock_import.side_effect = import_side_effect

            result = send_email_with_retry(
                to="test@example.com",
                subject="Test",
                html_body="<p>Test</p>"
            )

            assert result.success is False
            assert "not installed" in result.failure_reason


# =============================================================================
# Test: Email Result Tracking
# =============================================================================

def test_email_result_dataclass():
    """EmailResult is a proper dataclass."""
    result = EmailResult(
        success=True,
        email_id="test-123",
        sent_at=None,
        failure_reason=None,
        attempts=1
    )

    assert result.success is True
    assert result.email_id == "test-123"
    assert result.attempts == 1


def test_email_result_default_values():
    """EmailResult has sensible defaults."""
    result = EmailResult(success=False, attempts=1)

    assert result.success is False
    assert result.email_id is None
    assert result.sent_at is None
    assert result.failure_reason is None
    assert result.attempts == 1


# =============================================================================
# Test: Convenience Function
# =============================================================================

@patch("app.services.email_service.send_email_with_retry")
def test_send_email_single_attempt(mock_retry):
    """send_email uses max_retries=1."""
    mock_retry.return_value = EmailResult(
        success=True,
        email_id="email-123",
        attempts=1
    )

    result = send_email(
        to="test@example.com",
        subject="Test",
        html_body="<p>Test</p>"
    )

    # Verify called with max_retries=1
    call_kwargs = mock_retry.call_args[1]
    assert call_kwargs["max_retries"] == 1
    assert result.success is True


@patch("app.services.email_service.send_email_with_retry")
def test_send_email_passes_all_params(mock_retry):
    """send_email passes all parameters."""
    mock_retry.return_value = EmailResult(success=True, attempts=1)

    send_email(
        to="test@example.com",
        subject="Test",
        html_body="<p>Test</p>",
        from_address="custom@example.com"
    )

    mock_retry.assert_called_once()
    # Check the keyword arguments
    call_kwargs = mock_retry.call_args[1]
    assert call_kwargs["from_address"] == "custom@example.com"
    assert call_kwargs["max_retries"] == 1


# =============================================================================
# Test: Retry Behavior with Mocked resend
# =============================================================================

def test_retry_behavior_with_mock():
    """Test retry mechanism with mocked resend."""
    import resend
    
    call_count = [0]
    
    def mock_send(params):
        call_count[0] += 1
        if call_count[0] < 3:
            raise Exception(f"Attempt {call_count[0]} failed")
        return {"id": "email_123"}
    
    original_send = resend.Emails.send
    resend.Emails.send = mock_send
    
    try:
        with patch.dict("os.environ", {"RESEND_API_KEY": "test_key_123"}):
            result = send_email_with_retry(
                to="recipient@example.com",
                subject="Test",
                html_body="<p>Test</p>",
                max_retries=3,
                backoff_base=0.01
            )
            
            assert result.success is True
            assert result.attempts == 3
    finally:
        resend.Emails.send = original_send


def test_all_retries_fail():
    """Test all retries exhausted returns failure."""
    import resend
    
    original_send = resend.Emails.send
    resend.Emails.send = lambda p: (_ for _ in ()).throw(Exception("Always fails"))
    
    try:
        with patch.dict("os.environ", {"RESEND_API_KEY": "test_key_123"}):
            result = send_email_with_retry(
                to="recipient@example.com",
                subject="Test",
                html_body="<p>Test</p>",
                max_retries=3,
                backoff_base=0.01
            )
            
            assert result.success is False
            assert "Always fails" in result.failure_reason
    finally:
        resend.Emails.send = original_send


def test_max_retries_limit():
    """Test that max_retries parameter limits attempts."""
    import resend
    
    call_count = [0]
    
    def mock_send(params):
        call_count[0] += 1
        raise Exception("Always fails")
    
    original_send = resend.Emails.send
    resend.Emails.send = mock_send
    
    try:
        with patch.dict("os.environ", {"RESEND_API_KEY": "test_key_123"}):
            result = send_email_with_retry(
                to="recipient@example.com",
                subject="Test",
                html_body="<p>Test</p>",
                max_retries=2,
                backoff_base=0.01
            )
            
            # Should have attempted exactly 2 times
            assert call_count[0] == 2
            assert result.attempts == 2
    finally:
        resend.Emails.send = original_send