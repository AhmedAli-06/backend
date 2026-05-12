"""
Scheduler Service - Automated background tasks for ML model retraining.

Manages:
  - Weekly model retraining (Sundays at 2am UTC)
  - Health monitoring and failure alerts
  - Status tracking via shared global state
"""

import logging
import traceback
from datetime import UTC, datetime

# APScheduler is available from main.py import
# We use async-safe scheduling via AsyncIOScheduler

logger = logging.getLogger(__name__)

# Shared status dict — imported by app.routers.ml for /api/admin/ml/health
# Structure matches MLHealthResponse:
#   last_trained: ISO datetime string or None
#   status: "success" | "failed: <message>" | "pending"
#   model_version: str
#   is_training: bool
#   last_error: str | None
ml_training_status = {
    "last_trained": datetime.now(UTC).isoformat(),
    "status": "success",
    "model_version": "1.0.0",
    "is_training": False,
    "last_error": None,
}


def retrain_model() -> dict:
    """
    Retrain all ML models for every user-asset pair.

    This is the core function called by the weekly APScheduler job.
    It trains fresh Isolation Forest models from generated data and
    updates the shared ML status so /api/admin/ml/health reflects the result.

    Returns:
        dict with keys: success (bool), trained_count (int), failed_count (int),
        error (str or None)
    """
    from app.ml.train import list_models, train_model

    success = True
    trained_count = 0
    failed_count = 0
    error_msg = None

    logger.info("[Scheduler] Starting weekly ML model retraining")

    try:
        # Import within function to avoid circular imports at module load
        ml_training_status["is_training"] = True
        ml_training_status["status"] = "running"
        ml_training_status["last_error"] = None

        # Discover existing models (user-asset pairs to retrain)
        existing_models = list_models()

        if not existing_models:
            logger.info("[Scheduler] No existing models found, training demo model")
            # Create at least one demo model so health check shows models_loaded=True
            train_model("demo-user-001", "demo-asset-001", n_normal=200, n_anomaly=30)
            trained_count = 1
        else:
            logger.info(f"[Scheduler] Retraining {len(existing_models)} model(s)")
            for model_file in existing_models:
                try:
                    # model file format: {user_id}_{asset_id}.pkl
                    parts = model_file.replace(".pkl", "").split("_", 1)
                    if len(parts) == 2:
                        user_id, asset_id = parts
                        train_model(user_id, asset_id, n_normal=200, n_anomaly=30)
                        trained_count += 1
                        logger.info(f"[Scheduler] Retrained model: {user_id}/{asset_id}")
                    else:
                        logger.warning(f"[Scheduler] Skipping malformed model filename: {model_file}")
                except Exception as e:
                    logger.error(f"[Scheduler] Failed to retrain {model_file}: {e}")
                    failed_count += 1
                    # Continue with other models

        if trained_count > 0:
            ml_training_status["last_trained"] = datetime.now(UTC).isoformat()
            ml_training_status["status"] = "success"
            ml_training_status["model_version"] = bump_version(ml_training_status["model_version"])
            logger.info(
                f"[Scheduler] Model retrained successfully, metrics: "
                f"trained={trained_count} failed={failed_count}"
            )
        elif existing_models:
            # All failed
            success = False
            error_msg = f"All {len(existing_models)} models failed to retrain"
            ml_training_status["status"] = f"failed: {error_msg}"
            ml_training_status["last_error"] = error_msg
            logger.error(f"[Scheduler] {error_msg}")

    except Exception as e:
        success = False
        tb = traceback.format_exc()
        error_msg = str(e)
        ml_training_status["status"] = f"failed: {error_msg}"
        ml_training_status["last_error"] = error_msg
        logger.error(f"[Scheduler] Model retraining failed: {error_msg}\n{tb}")

        # Send failure alert via Resend
        _send_retrain_failure_alert(error_msg)

    finally:
        ml_training_status["is_training"] = False

    return {
        "success": success,
        "trained_count": trained_count,
        "failed_count": failed_count,
        "error": error_msg,
    }


def bump_version(version: str) -> str:
    """Bump patch version: 1.0.0 -> 1.0.1"""
    parts = version.split(".")
    if len(parts) == 3:
        return f"{parts[0]}.{parts[1]}.{int(parts[2]) + 1}"
    return version


def _send_retrain_failure_alert(error_message: str):
    """
    Send an alert email when weekly retraining fails.
    Uses the same Resend setup as alert_service.py.
    """
    import os

    resend_api_key = os.getenv("RESEND_API_KEY")
    alert_email = os.getenv("ALERT_EMAIL")

    if not resend_api_key or not alert_email:
        logger.warning(
            f"[Scheduler] Resend not configured. Would send alert: "
            f"ML retraining failed: {error_message}"
        )
        return

    try:
        from datetime import datetime

        import resend

        resend.api_key = resend_api_key

        html_content = f"""
        <html>
        <body style="font-family: Arial, sans-serif; padding: 20px;">
            <h2 style="color: #dc2626;">ContextShield ML Retraining Failed</h2>
            <div style="background: #fef2f2; padding: 15px; border-radius: 8px; border: 1px solid #fecaca;">
                <h3 style="margin-top: 0;">Weekly ML Retraining Failed</h3>
                <p><strong>Error:</strong> {error_message}</p>
                <p><strong>Time:</strong> {datetime.now(UTC).isoformat()}</p>
                <p>Please investigate immediately. Models may be outdated.</p>
            </div>
            <p style="color: #6b7280; font-size: 12px; margin-top: 20px;">
                This is an automated alert from ContextShield Physical Security Platform.
            </p>
        </body>
        </html>
        """

        response = resend.Emails.send({
            "from": "alerts@contextshield.io",
            "to": alert_email,
            "subject": f"ML retraining failed: {error_message}",
            "html": html_content,
        })

        logger.info(f"[Scheduler] Failure alert sent: {response.get('id', 'unknown')}")

    except Exception as e:
        logger.error(f"[Scheduler] Failed to send failure alert email: {e}")


def register_weekly_retrain_job(scheduler) -> None:
    """
    Register the weekly ML retraining job with an AsyncIOScheduler instance.

    Args:
        scheduler: an AsyncIOScheduler instance (from main.py or tests)
    """
    scheduler.add_job(
        _async_retrain_wrapper,
        "cron",
        day_of_week="sun",
        hour=2,
        minute=0,
        id="ml_weekly_retrain",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=3600,  # 1-hour grace for missed runs
    )
    logger.info("[Scheduler] Weekly ML retraining job registered (Sundays 2am UTC)")


async def _async_retrain_wrapper():
    """
    Async wrapper so APScheduler can call the sync retrain_model function.
    APScheduler's async scheduler expects async functions.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, retrain_model)
    return result
