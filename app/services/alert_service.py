"""
Alert Service - Creates alerts and sends email notifications

Handles:
  - Alert creation in database
  - Email notifications via Resend API with retry logic
  - Alert severity classification
  - Delivery confirmation tracking
"""

import os
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.services.email_service import EmailResult, send_email_with_retry


def create_alert(
    db: AsyncSession,
    tenant_id: UUID,
    user_id: UUID | None,
    asset_id: UUID,
    session_id: UUID | None,
    severity: str,
    alert_type: str,
    title: str,
    description: str,
    trust_score: float,
    anomaly_score: float | None = None,
    top_features: dict | None = None,
    user_name: str | None = None,
    user_email: str | None = None,
    asset_name: str | None = None,
    recommended_action: str | None = None
) -> Alert:
    """
    Create an alert in the database and send email if critical.

    Args:
        db: Database session
        tenant_id: Tenant UUID
        user_id: User UUID (if known)
        asset_id: Asset UUID
        session_id: Session UUID (if session exists)
        severity: "critical", "warning", or "info"
        alert_type: Type of alert (e.g., "low_trust_score", "ghost_access", "anomaly_detected")
        title: Alert title
        description: Alert description
        trust_score: Trust score at time of alert
        anomaly_score: Optional anomaly score
        top_features: Optional dict of contributing features
        user_name: Optional user name for email
        user_email: Optional user email for email
        asset_name: Optional asset name for email
        recommended_action: Optional recommended action for email

    Returns:
        Alert: Created alert instance
    """
    # Initialize notification tracking
    notifications_sent = {
        "email_sent": False,
        "email_sent_at": None,
        "email_failure_reason": None,
        "email_attempts": 0
    }

    alert = Alert(
        tenant_id=tenant_id,
        user_id=user_id,
        asset_id=asset_id,
        session_id=session_id,
        severity=severity,
        alert_type=alert_type,
        title=title,
        description=description,
        trust_score_at_trigger=trust_score,
        anomaly_score_at_trigger=anomaly_score,
        top_features=top_features,
        status="open",
        triggered_at=datetime.now(UTC),
        notifications_sent=notifications_sent
    )

    db.add(alert)

    # Send email for critical alerts with retry logic
    if severity == "critical":
        result = send_alert_email_with_tracking(
            title=title,
            description=description,
            trust_score=trust_score,
            anomaly_score=anomaly_score,
            user_name=user_name,
            user_email=user_email,
            asset_name=asset_name,
            recommended_action=recommended_action
        )

        # Update alert with delivery status
        alert.notifications_sent = {
            "email_sent": result.success,
            "email_sent_at": result.sent_at.isoformat() if result.sent_at else None,
            "email_failure_reason": result.failure_reason,
            "email_attempts": result.attempts,
            "email_id": result.email_id
        }

    return alert


def send_alert_email_with_tracking(
    title: str,
    description: str,
    trust_score: float,
    anomaly_score: float | None = None,
    user_name: str | None = None,
    user_email: str | None = None,
    asset_name: str | None = None,
    recommended_action: str | None = None
) -> EmailResult:
    """
    Send alert email via Resend API with retry logic and full tracking.

    Args:
        title: Alert title
        description: Alert description
        trust_score: Trust score at trigger time
        anomaly_score: Optional anomaly score
        user_name: Optional user name
        user_email: Optional user email
        asset_name: Optional asset name
        recommended_action: Optional recommended action

    Returns:
        EmailResult: Contains success status, email_id, sent_at, failure_reason, attempts
    """
    alert_email = os.getenv("ALERT_EMAIL")

    if not alert_email:
        print(f"[ALERT] ALERT_EMAIL not configured. Would send: {title}")
        return EmailResult(
            success=False,
            failure_reason="ALERT_EMAIL not configured",
            attempts=1
        )

    # Determine severity for display
    severity = "HIGH" if trust_score < 0.2 else "MEDIUM"

    # Build the alert email content with all required fields
    html_content = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">
        <h2 style="color: #dc2626;">🚨 ContextShield Alert: {severity}</h2>
        <div style="background: #fef2f2; padding: 15px; border-radius: 8px; border: 1px solid #fecaca;">
            <h3 style="margin-top: 0; color: #991b1b;">{title}</h3>
            <p><strong>Description:</strong> {description}</p>
    """

    # Include all required fields
    if user_name:
        html_content += f"<p><strong>User:</strong> {user_name}"
        if user_email:
            html_content += f" ({user_email})"
        html_content += "</p>"

    if asset_name:
        html_content += f"<p><strong>Asset:</strong> {asset_name}</p>"

    html_content += f"""
            <p><strong>Time:</strong> {datetime.now(UTC).isoformat()}</p>
            <p><strong>Trust Score:</strong> {trust_score:.2f}</p>
    """

    if anomaly_score is not None:
        html_content += f"<p><strong>Anomaly Score:</strong> {anomaly_score:.2f}</p>"

    # Add severity badge
    html_content += f"""
            <p><strong>Severity:</strong> <span style="background: #dc2626; color: white; padding: 2px 8px; border-radius: 4px;">{severity}</span></p>
    """

    # Add recommended action if provided
    if recommended_action:
        html_content += f"""
            <div style="background: #eff6ff; padding: 12px; border-radius: 8px; border: 1px solid #bfdbfe; margin-top: 10px;">
                <p style="margin: 0; color: #1e40af;"><strong>📋 Recommended Action:</strong> {recommended_action}</p>
            </div>
        """

    html_content += """
        </div>
        <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
            This is an automated alert from ContextShield Physical Security Platform.
        </p>
    </body>
    </html>
    """

    # Build plain text version for subject
    subject_fields = []
    if user_name:
        subject_fields.append(user_name)
    if asset_name:
        subject_fields.append(asset_name)
    subject_suffix = " - " + " @ ".join(subject_fields) if subject_fields else ""

    subject = f"[ContextShield] Alert: {severity} - {title}{subject_suffix}"

    # Use the email service with retry logic
    return send_email_with_retry(
        to=alert_email,
        subject=subject,
        html_body=html_content,
        from_address="alerts@contextshield.io",
        max_retries=3,
        backoff_base=1.0  # 1s, 2s, 4s - adjusted for faster recovery
    )


def send_alert_email(
    title: str,
    description: str,
    trust_score: float,
    anomaly_score: float | None = None
) -> bool:
    """
    Send alert email via Resend API (legacy function for backward compatibility).

    Args:
        title: Alert title
        description: Alert description
        trust_score: Trust score at trigger time
        anomaly_score: Optional anomaly score

    Returns:
        bool: True if email sent successfully
    """
    result = send_alert_email_with_tracking(
        title=title,
        description=description,
        trust_score=trust_score,
        anomaly_score=anomaly_score
    )
    return result.success


def classify_severity(trust_score: float, anomaly_score: float | None = None) -> str:
    """
    Classify alert severity based on trust score and anomaly score.

    Args:
        trust_score: The trust score at trigger time
        anomaly_score: Optional anomaly score

    Returns:
        str: "critical", "warning", or "info"
    """
    if trust_score < 0.2:
        return "critical"

    if trust_score < 0.4:
        return "warning"

    if anomaly_score and anomaly_score > 0.7:
        return "warning"

    return "info"


async def create_access_alert(
    db: AsyncSession,
    tenant_id: UUID,
    user_id: UUID | None,
    asset_id: UUID,
    session_id: UUID | None,
    trust_score: float,
    feature_vector: dict,
    user_name: str | None = None,
    user_email: str | None = None,
    asset_name: str | None = None
) -> Alert:
    """
    Convenience function to create an alert for anomalous access.

    Analyzes the feature vector to determine alert type and severity.
    """
    reasons = []
    recommended_actions = []

    if feature_vector.get("project_score", 1.0) < 0.3:
        reasons.append("out of project scope")
        recommended_actions.append("Verify user project authorization")
    if feature_vector.get("temporal_score", 1.0) < 0.3:
        reasons.append("off hours access")
        recommended_actions.append("Confirm access necessity with supervisor")
    if feature_vector.get("anomaly_score", 0.0) > 0.6:
        reasons.append("unusual behaviour pattern")
        recommended_actions.append("Review access patterns with security team")
    if feature_vector.get("history_score", 0.0) < 0.1:
        reasons.append("rarely accesses this asset")
        recommended_actions.append("Verify identity with MFA or security")

    if not reasons:
        reasons.append("low trust score")
        recommended_actions.append("Monitor user activity closely")

    severity = classify_severity(
        trust_score,
        feature_vector.get("anomaly_score")
    )

    # Build recommended action text
    recommended_action = "; ".join(recommended_actions) if recommended_actions else "Review alert details"

    title = f"Low trust score ({trust_score:.2f}) - Access Alert"
    description = f"Trust score {trust_score:.3f}. Flags: {', '.join(reasons)}"

    return create_alert(
        db=db,
        tenant_id=tenant_id,
        user_id=user_id,
        asset_id=asset_id,
        session_id=session_id,
        severity=severity,
        alert_type="anomalous_access",
        title=title,
        description=description,
        trust_score=trust_score,
        anomaly_score=feature_vector.get("anomaly_score"),
        top_features={
            "project_score": feature_vector.get("project_score"),
            "temporal_score": feature_vector.get("temporal_score"),
            "baseline_score": feature_vector.get("baseline_score"),
            "history_score": feature_vector.get("history_score"),
            "anomaly_score": feature_vector.get("anomaly_score")
        },
        user_name=user_name,
        user_email=user_email,
        asset_name=asset_name,
        recommended_action=recommended_action
    )
