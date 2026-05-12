"""
Train anomaly detection models for user-asset pairs.

Uses Isolation Forest to learn normal access patterns and detect anomalies.
Supports: synthetic data generation, train/test evaluation, model persistence,
manual triggering, and scheduled retraining (APScheduler).
"""

import logging
import os
import pickle
from datetime import UTC, datetime
from uuid import UUID

from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from app.ml.generate_data import (
    generate_large_dataset,
    generate_training_data,
    get_extended_features,
    get_feature_columns,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODEL_DIR = "ml/models"
DEFAULT_MODEL_PATH = f"{MODEL_DIR}/anomaly_iforest.joblib"


class TrainingMetrics:
    """Container for training evaluation metrics."""

    def __init__(
        self,
        precision: float,
        recall: float,
        f1: float,
        n_train: int,
        n_test: int,
        n_anomalies: int
    ):
        self.precision = precision
        self.recall = recall
        self.f1 = f1
        self.n_train = n_train
        self.n_test = n_test
        self.n_anomalies = n_anomalies
        self.timestamp = datetime.now(UTC).isoformat()

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "n_train": self.n_train,
            "n_test": self.n_test,
            "n_anomalies": self.n_anomalies,
            "timestamp": self.timestamp
        }

    def __repr__(self) -> str:
        return (
            f"TrainingMetrics(precision={self.precision:.4f}, "
            f"recall={self.recall:.4f}, f1={self.f1:.4f}, "
            f"n_train={self.n_train}, n_test={self.n_test})"
        )


def train_model(
    user_id: str | UUID,
    asset_id: str | UUID,
    n_normal: int = 200,
    n_anomaly: int = 30
) -> str:
    """
    Train an Isolation Forest model for a user-asset pair.

    Args:
        user_id: User ID (string or UUID)
        asset_id: Asset ID (string or UUID)
        n_normal: Number of normal samples to generate
        n_anomaly: Number of anomaly samples to generate

    Returns:
        str: Path to saved model
    """
    # Convert UUIDs to strings if needed
    user_id_str = str(user_id)
    asset_id_str = str(asset_id)

    # Generate training data
    df = generate_training_data(user_id_str, asset_id_str, n_normal, n_anomaly)

    # Extract features
    features = get_feature_columns()
    X = df[features].values
    y = df["label"].values

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,  # Expected anomaly rate
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    # Ensure directory exists
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    model_path = f"{MODEL_DIR}/{user_id_str}_{asset_id_str}.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    logger.info(f"Model trained and saved: {model_path}")
    return model_path


def train_model_from_data(
    user_id: str,
    asset_id: str,
    X,
    y=None
) -> str:
    """
    Train a model from provided feature data.

    Args:
        user_id: User ID string
        asset_id: Asset ID string
        X: Feature array (n_samples, n_features)
        y: Optional labels (not used by Isolation Forest)

    Returns:
        str: Path to saved model
    """
    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X)

    # Ensure directory exists
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Save model
    model_path = f"{MODEL_DIR}/{user_id}_{asset_id}.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(model, f)

    return model_path


def train_and_persist(
    n_records: int = 1000,
    contamination: float = 0.1,
    use_extended_features: bool = False,
    model_path: str | None = None
) -> tuple[str, TrainingMetrics]:
    """
    Automated training pipeline: generate data → train → evaluate → persist.

    This function:
    1. Generates synthetic training data (normal + anomaly patterns)
    2. Splits into train/test sets
    3. Trains Isolation Forest with configurable contamination
    4. Evaluates on test set (precision, recall, F1)
    5. Persists model to disk
    6. Logs evaluation metrics

    Args:
        n_records: Target number of records for training
        contamination: Expected anomaly rate (0.0 to 0.5)
        use_extended_features: Use extended feature set (includes frequency, duration, etc.)
        model_path: Optional custom path for model persistence

    Returns:
        tuple: (path to saved model, TrainingMetrics)
    """
    logger.info(f"Starting training pipeline with {n_records} records...")

    # Ensure model directory exists
    os.makedirs(MODEL_DIR, exist_ok=True)

    # Generate synthetic training data
    df = generate_large_dataset(
        n_records=n_records,
        n_users=10,
        n_assets=20
    )
    logger.info(f"Generated {len(df)} records with {df['label'].sum()} anomalies")

    # Select feature columns
    features = get_extended_features() if use_extended_features else get_feature_columns()
    X = df[features].values
    y = df["label"].values

    # Split into train/test sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    logger.info(f"Train: {len(X_train)}, Test: {len(X_test)}")

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=contamination,
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train)
    logger.info("Model training complete")

    # Evaluate on test set
    # Isolation Forest predicts: 1 for inliers, -1 for outliers
    y_pred = model.predict(X_test)
    # Convert: -1 (outlier/anomaly) -> 1, 1 (inlier/normal) -> 0
    y_pred_binary = (y_pred == -1).astype(int)

    # Calculate metrics
    precision = precision_score(y_test, y_pred_binary, zero_division=0)
    recall = recall_score(y_test, y_pred_binary, zero_division=0)
    f1 = f1_score(y_test, y_pred_binary, zero_division=0)

    metrics = TrainingMetrics(
        precision=precision,
        recall=recall,
        f1=f1,
        n_train=len(X_train),
        n_test=len(X_test),
        n_anomalies=int(y_test.sum())
    )

    logger.info(f"Evaluation metrics: {metrics}")

    # Persist model
    save_path = model_path or DEFAULT_MODEL_PATH
    with open(save_path, "wb") as f:
        pickle.dump(model, f)
    logger.info(f"Model persisted to: {save_path}")

    return save_path, metrics


def load_model(model_path: str | None = None):
    """
    Load a trained model from disk.

    Args:
        model_path: Path to model file. Defaults to DEFAULT_MODEL_PATH.

    Returns:
        IsolationForest model or None if not found
    """
    path = model_path or DEFAULT_MODEL_PATH

    if not os.path.exists(path):
        logger.warning(f"Model not found: {path}")
        return None

    with open(path, "rb") as f:
        return pickle.load(f)


def load_default_model():
    """Load the default anomaly detection model."""
    return load_model(DEFAULT_MODEL_PATH)


def model_exists(model_path: str | None = None) -> bool:
    """Check if model exists."""
    path = model_path or DEFAULT_MODEL_PATH
    return os.path.exists(path)


def delete_model(user_id: str, asset_id: str) -> bool:
    """Delete a trained model."""
    model_path = f"{MODEL_DIR}/{user_id}_{asset_id}.pkl"

    if os.path.exists(model_path):
        os.remove(model_path)
        return True
    return False


def delete_default_model() -> bool:
    """Delete the default model."""
    if os.path.exists(DEFAULT_MODEL_PATH):
        os.remove(DEFAULT_MODEL_PATH)
        return True
    return False


def list_models() -> list[str]:
    """List all trained models."""
    if not os.path.exists(MODEL_DIR):
        return []
    return [f for f in os.listdir(MODEL_DIR) if f.endswith(".pkl") or f.endswith(".joblib")]


def predict_anomaly(model, features: list[float]) -> tuple[int, float]:
    """
    Make prediction with trained model.

    Args:
        model: Trained IsolationForest model
        features: List of feature values [hour, weekday, project_score, temporal_score, history_score]

    Returns:
        tuple: (prediction: 0=normal, 1=anomaly, anomaly_score: 0.0-1.0)
    """
    import numpy as np

    X = np.array([features])
    raw_score = model.decision_function(X)[0]
    # Normalize to 0-1 where 1 = most anomalous
    anomaly_score = max(0.0, min(1.0, -raw_score + 0.5))
    prediction = 1 if model.predict(X)[0] == -1 else 0

    return prediction, float(anomaly_score)


# Scheduler configuration for weekly retraining
def scheduled_retraining():
    """
    Retraining function for APScheduler.
    Called weekly to refresh the model with latest synthetic data.
    """
    logger.info("Starting scheduled model retraining...")
    try:
        path, metrics = train_and_persist(n_records=1000)
        logger.info(f"Scheduled retraining complete: {path}")
        logger.info(f"Metrics: precision={metrics.precision:.4f}, recall={metrics.recall:.4f}, f1={metrics.f1:.4f}")
    except Exception as e:
        logger.error(f"Scheduled retraining failed: {e}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) >= 3:
        # CLI: python train.py <user_id> <asset_id>
        user_id = sys.argv[1]
        asset_id = sys.argv[2]
        path = train_model(user_id, asset_id)
        print(f"Trained model: {path}")
    elif "--auto" in sys.argv:
        # Automated training pipeline
        path, metrics = train_and_persist(n_records=1000)
        print(f"Model trained and saved: {path}")
        print(f"Metrics: {metrics}")
    else:
        # Demo: train a sample model with evaluation
        print("Running automated training pipeline...")
        path, metrics = train_and_persist(n_records=1000)
        print(f"\nModel saved: {path}")
        print("Evaluation metrics:")
        for key, value in metrics.to_dict().items():
            print(f"  {key}: {value}")
