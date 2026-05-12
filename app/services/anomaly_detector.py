"""
Anomaly Detector Service - ML-based behavioral anomaly detection

Uses Isolation Forest to detect anomalous access patterns based on:
  - Hour of day
  - Day of week
  - Project score
  - Temporal score
  - Historical access frequency

Supports automated training pipeline with evaluation metrics.
"""

import os
import pickle
from uuid import UUID

import numpy as np
from sklearn.ensemble import IsolationForest

from app.ml.train import (
    load_model as ml_load_model,
    model_exists as ml_model_exists,
    train_and_persist,
)
from app.services.baseline_service import get_model_path

MODEL_DIR = "ml/models"
DEFAULT_MODEL_PATH = f"{MODEL_DIR}/anomaly_iforest.joblib"


def get_anomaly_score(
    user_id: UUID,
    asset_id: UUID,
    context: dict,
    session_history: list | None = None
) -> float:
    """
    Compute anomaly score for a user-asset access attempt.

    Args:
        user_id: UUID of the user
        asset_id: UUID of the asset
        context: dict with project_score, temporal_score, baseline_score, history_score, hour, weekday
        session_history: optional list of recent session data

    Returns:
        float: anomaly score from 0.0 (normal) to 1.0 (highly anomalous)
    """
    model_path = get_model_path(user_id, asset_id)

    # Build feature vector
    features = np.array([[
        context.get("hour", 12),
        context.get("weekday", 0),
        context.get("project_score", 0.5),
        context.get("temporal_score", 0.5),
        context.get("history_score", 0.5)
    ]])

    # If model doesn't exist, return neutral score with slight randomness
    if not os.path.exists(model_path):
        return 0.3

    try:
        with open(model_path, "rb") as f:
            model: IsolationForest = pickle.load(f)

        # Isolation Forest returns: 1 for inliers, -1 for outliers
        # decision_function returns: higher = more normal, lower = more anomalous
        raw_score = model.decision_function(features)[0]

        # Normalize to 0-1 where 1 = most anomalous
        # Raw scores typically range from -0.5 to 0.5
        anomaly_score = max(0.0, min(1.0, -raw_score + 0.5))

        return round(float(anomaly_score), 3)

    except Exception as e:
        print(f"Error loading anomaly model: {e}")
        return 0.3


def train_model(
    user_id: UUID,
    asset_id: UUID,
    normal_data: list[dict],
    anomaly_data: list[dict] | None = None
) -> str:
    """
    Train an Isolation Forest model for a user-asset pair.

    Args:
        user_id: UUID of the user
        asset_id: UUID of the asset
        normal_data: list of dicts with features (hour, weekday, project_score, temporal_score, history_score)
        anomaly_data: optional list of anomalous access patterns

    Returns:
        str: path to saved model
    """
    # Combine features from normal data
    features = []
    labels = []

    for record in normal_data:
        features.append([
            record.get("hour", 12),
            record.get("weekday", 0),
            record.get("project_score", 0.5),
            record.get("temporal_score", 0.5),
            record.get("history_score", 0.5)
        ])
        labels.append(0)  # 0 = normal

    # Add anomaly data if provided
    if anomaly_data:
        for record in anomaly_data:
            features.append([
                record.get("hour", 12),
                record.get("weekday", 0),
                record.get("project_score", 0.5),
                record.get("temporal_score", 0.5),
                record.get("history_score", 0.5)
            ])
            labels.append(1)  # 1 = anomaly

    X = np.array(features)

    # Train Isolation Forest
    # contamination=0.1 means we expect ~10% anomalies
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    # Ensure model directory exists
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    model_path = get_model_path(user_id, asset_id)
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    return model_path


def delete_model(user_id: UUID, asset_id: UUID) -> bool:
    """Delete the trained model for a user-asset pair."""
    model_path = get_model_path(user_id, asset_id)
    if os.path.exists(model_path):
        os.remove(model_path)
        return True
    return False


def model_exists(user_id: UUID, asset_id: UUID) -> bool:
    """Check if a trained model exists for this user-asset pair."""
    return os.path.exists(get_model_path(user_id, asset_id))


def train_global_model(
    n_records: int = 1000,
    contamination: float = 0.1,
    use_extended_features: bool = False
) -> tuple[str, dict]:
    """
    Train and persist a global anomaly detection model.

    This function:
    1. Generates synthetic training data (normal + anomaly patterns)
    2. Splits into train/test sets
    3. Trains Isolation Forest with configurable contamination
    4. Evaluates on test set (precision, recall, F1)
    5. Persists model to ml/models/anomaly_iforest.joblib
    6. Returns path and evaluation metrics

    Args:
        n_records: Target number of records for training
        contamination: Expected anomaly rate (0.0 to 0.5)
        use_extended_features: Use extended feature set (includes frequency, duration, etc.)

    Returns:
        tuple: (path to saved model, metrics dict)
    """
    model_path, metrics = train_and_persist(
        n_records=n_records,
        contamination=contamination,
        use_extended_features=use_extended_features,
        model_path=DEFAULT_MODEL_PATH
    )
    return model_path, metrics.to_dict()


def get_global_anomaly_score(
    context: dict,
    session_history: list | None = None
) -> float:
    """
    Compute anomaly score using the global model.

    Args:
        context: dict with project_score, temporal_score, baseline_score, history_score, hour, weekday
        session_history: optional list of recent session data

    Returns:
        float: anomaly score from 0.0 (normal) to 1.0 (highly anomalous)
    """
    model = ml_load_model(DEFAULT_MODEL_PATH)

    # Build feature vector
    features = np.array([[
        context.get("hour", 12),
        context.get("weekday", 0),
        context.get("project_score", 0.5),
        context.get("temporal_score", 0.5),
        context.get("history_score", 0.5)
    ]])

    if model is None:
        return 0.3

    # Isolation Forest returns: higher = more normal, lower = more anomalous
    raw_score = model.decision_function(features)[0]

    # Normalize to 0-1 where 1 = most anomalous
    anomaly_score = max(0.0, min(1.0, -raw_score + 0.5))

    return round(float(anomaly_score), 3)


def global_model_exists() -> bool:
    """Check if the global anomaly model exists."""
    return ml_model_exists(DEFAULT_MODEL_PATH)


def trigger_retraining() -> tuple[str, dict]:
    """
    Manually trigger model retraining.

    Returns:
        tuple: (path to saved model, metrics dict)
    """
    return train_global_model(n_records=1000)
