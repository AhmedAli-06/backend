"""
Email Service - Handles email delivery with retry logic and delivery confirmation.

Features:
    - Exponential backoff retry (1s, 4s, 16s for 3 attempts)
    - Delivery status tracking
    - Configurable retry parameters
"""

import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


@dataclass
class EmailResult:
    """Result of an email send operation."""
    success: bool
    email_id: str | None = None
    sent_at: datetime | None = None
    failure_reason: str | None = None
    attempts: int = 0


def send_email_with_retry(
    to: str,
    subject: str,
    html_body: str,
    from_address: str | None = None,
    max_retries: int = 3,
    backoff_base: float = 1.0
) -> EmailResult:
    """
    Send an email with retry logic and exponential backoff.

    Args:
        to: Recipient email address
        subject: Email subject line
        html_body: HTML content of the email
        from_address: Optional sender address (defaults to alerts@contextshield.io)
        max_retries: Maximum number of retry attempts (default: 3)
        backoff_base: Base delay for exponential backoff in seconds (default: 1.0)

    Returns:
        EmailResult: Contains success status, email_id, sent_at, failure_reason, attempts
    """
    from_address = from_address or os.getenv("ALERT_EMAIL_FROM", "alerts@contextshield.io")
    resend_api_key = os.getenv("RESEND_API_KEY")

    if not resend_api_key:
        logger.warning(f"[EMAIL] RESEND_API_KEY not configured. Would send to: {to}")
        return EmailResult(
            success=False,
            failure_reason="RESEND_API_KEY not configured",
            attempts=1
        )

    # Import resend here to avoid import errors if not installed
    try:
        import resend
        resend.api_key = resend_api_key
    except ImportError:
        logger.warning("[EMAIL] resend package not installed. Would send to: {to}")
        return EmailResult(
            success=False,
            failure_reason="resend package not installed",
            attempts=1
        )

    last_error = None

    for attempt in range(max_retries):
        try:
            response = resend.Emails.send({
                "from": from_address,
                "to": to,
                "subject": subject,
                "html": html_body
            })

            email_id = response.get("id", "unknown") if isinstance(response, dict) else "unknown"

            logger.info(f"[EMAIL] Email sent successfully (attempt {attempt + 1}): {email_id}")

            return EmailResult(
                success=True,
                email_id=email_id,
                sent_at=datetime.now(UTC),
                attempts=attempt + 1
            )

        except Exception as e:
            last_error = str(e)
            logger.warning(f"[EMAIL] Attempt {attempt + 1}/{max_retries} failed: {last_error}")

            # Don't sleep after the last attempt
            if attempt < max_retries - 1:
                # Exponential backoff: 1s, 4s, 16s (base^attempt)
                delay = backoff_base * (2 ** attempt)
                logger.info(f"[EMAIL] Retrying in {delay} seconds...")
                time.sleep(delay)

    # All retries exhausted
    logger.error(f"[EMAIL] All {max_retries} attempts failed. Final error: {last_error}")
    return EmailResult(
        success=False,
        failure_reason=last_error or "Unknown error",
        attempts=max_retries
    )


def send_email(
    to: str,
    subject: str,
    html_body: str,
    from_address: str | None = None
) -> EmailResult:
    """
    Send an email without retry logic (single attempt).

    Args:
        to: Recipient email address
        subject: Email subject line
        html_body: HTML content of the email
        from_address: Optional sender address

    Returns:
        EmailResult: Contains success status, email_id, sent_at, failure_reason
    """
    return send_email_with_retry(
        to=to,
        subject=subject,
        html_body=html_body,
        from_address=from_address,
        max_retries=1  # Single attempt, no retry
    )
