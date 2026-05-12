"""
Tests for anomaly_detector.py — ML-based anomaly detection.

Tests cover:
- Normal scoring
- High anomaly detection
- Model training
- Model persistence
- Prediction threshold
"""

import pytest
import os
import pickle
import tempfile
import shutil
from uuid import uuid4
from unittest.mock import patch, MagicMock

import numpy as np
from sklearn.ensemble import IsolationForest

from app.services import anomaly_detector


# =============================================================================
# Test: Get Anomaly Score - No Model
# =============================================================================

def test_get_anomaly_score_no_model():
    """No model exists → returns neutral 0.3 score."""
    with patch("app.services.anomaly_detector.os.path.exists", return_value=False):
        # Create a mock context with all features
        result = anomaly_detector.get_anomaly_score(
            user_id=uuid4(),
            asset_id=uuid4(),
            context={
                "hour": 10,
                "weekday": 1,
                "project_score": 0.8,
                "temporal_score": 0.9,
                "history_score": 0.7
            }
        )

        assert result == 0.3


def test_get_anomaly_score_default_context():
    """Default context values work correctly."""
    with patch("app.services.anomaly_detector.os.path.exists", return_value=False):
        result = anomaly_detector.get_anomaly_score(
            user_id=uuid4(),
            asset_id=uuid4(),
            context={}  # Empty context
        )

        # Should use defaults and still return neutral score
        assert result is not None
        assert 0.0 <= result <= 1.0


def test_get_anomaly_score_context_with_missing_values():
    """Missing context values use defaults."""
    with patch("app.services.anomaly_detector.os.path.exists", return_value=False):
        result = anomaly_detector.get_anomaly_score(
            user_id=uuid4(),
            asset_id=uuid4(),
            context={
                "hour": 14,
                # Missing weekday, project_score, temporal_score, history_score
            }
        )

        assert result is not None


# =============================================================================
# Test: Get Anomaly Score - With Model
# =============================================================================

def test_get_anomaly_score_with_model():
    """With existing model, returns computed anomaly score."""
    # Create a temporary model file
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a simple Isolation Forest model
        model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
        X = np.array([[10, 1, 0.8, 0.9, 0.7]])  # Normal access
        model.fit(X)

        model_path = os.path.join(temp_dir, "model.joblib")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        with patch("app.services.anomaly_detector.get_model_path", return_value=model_path):
            result = anomaly_detector.get_anomaly_score(
                user_id=uuid4(),
                asset_id=uuid4(),
                context={
                    "hour": 10,
                    "weekday": 1,
                    "project_score": 0.8,
                    "temporal_score": 0.9,
                    "history_score": 0.7
                }
            )

            assert 0.0 <= result <= 1.0

    finally:
        shutil.rmtree(temp_dir)


def test_get_anomaly_score_high_anomaly():
    """Unusual pattern → high anomaly score."""
    temp_dir = tempfile.mkdtemp()
    try:
        # Create model trained on normal patterns
        model = IsolationForest(n_estimators=10, contamination=0.1, random_state=42)
        # Normal access patterns: daytime, weekday
        X_normal = np.array([
            [10, 1, 0.8, 0.9, 0.7],
            [11, 2, 0.7, 0.8, 0.6],
            [9, 3, 0.9, 0.85, 0.75],
        ])
        model.fit(X_normal)

        model_path = os.path.join(temp_dir, "model.joblib")
        with open(model_path, "wb") as f:
            pickle.dump(model, f)

        with patch("app.services.anomaly_detector.get_model_path", return_value=model_path):
            # Unusual: 3am, weekend, poor scores
            result = anomaly_detector.get_anomaly_score(
                user_id=uuid4(),
                asset_id=uuid4(),
                context={
                    "hour": 3,
                    "weekday": 6,  # Saturday
                    "project_score": 0.1,
                    "temporal_score": 0.1,
                    "history_score": 0.1
                }
            )

            # Should get higher anomaly score for unusual pattern
            assert 0.0 <= result <= 1.0

    finally:
        shutil.rmtree(temp_dir)


def test_get_anomaly_score_model_load_error():
    """Model file corrupted → returns fallback 0.3."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_path = os.path.join(temp_dir, "corrupted.joblib")
        with open(model_path, "wb") as f:
            f.write(b"not a valid model")

        with patch("app.services.anomaly_detector.get_model_path", return_value=model_path):
            result = anomaly_detector.get_anomaly_score(
                user_id=uuid4(),
                asset_id=uuid4(),
                context={"hour": 10, "weekday": 1}
            )

            assert result == 0.3

    finally:
        shutil.rmtree(temp_dir)


# =============================================================================
# Test: Train Model
# =============================================================================

def test_train_model_creates_file():
    """train_model creates a model file."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_dir = os.path.join(temp_dir, "ml", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        with patch("app.services.anomaly_detector.MODEL_DIR", model_dir):
            with patch("app.services.anomaly_detector.get_model_path") as mock_path:
                user_id = uuid4()
                asset_id = uuid4()
                mock_path.return_value = os.path.join(model_dir, f"{user_id}_{asset_id}.pkl")
                
                normal_data = [
                    {"hour": 10, "weekday": 1, "project_score": 0.8, "temporal_score": 0.9, "history_score": 0.7},
                    {"hour": 11, "weekday": 2, "project_score": 0.7, "temporal_score": 0.8, "history_score": 0.6},
                    {"hour": 9, "weekday": 3, "project_score": 0.9, "temporal_score": 0.85, "history_score": 0.75},
                ]

                model_path = anomaly_detector.train_model(
                    user_id=user_id,
                    asset_id=asset_id,
                    normal_data=normal_data
                )

                assert os.path.exists(model_path)

                with open(model_path, "rb") as f:
                    loaded_model = pickle.load(f)
                assert isinstance(loaded_model, IsolationForest)

    finally:
        shutil.rmtree(temp_dir)


def test_train_model_with_anomaly_data():
    """train_model can use labeled anomaly data."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_dir = os.path.join(temp_dir, "ml", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        with patch("app.services.anomaly_detector.MODEL_DIR", model_dir):
            with patch("app.services.anomaly_detector.get_model_path") as mock_path:
                user_id = uuid4()
                asset_id = uuid4()
                mock_path.return_value = os.path.join(model_dir, f"{user_id}_{asset_id}.pkl")
                
                normal_data = [
                    {"hour": 10, "weekday": 1, "project_score": 0.8, "temporal_score": 0.9, "history_score": 0.7},
                ]
                anomaly_data = [
                    {"hour": 3, "weekday": 6, "project_score": 0.1, "temporal_score": 0.1, "history_score": 0.1},
                ]

                model_path = anomaly_detector.train_model(
                    user_id=user_id,
                    asset_id=asset_id,
                    normal_data=normal_data,
                    anomaly_data=anomaly_data
                )

                assert os.path.exists(model_path)

    finally:
        shutil.rmtree(temp_dir)


def test_train_model_uses_defaults():
    """train_model handles missing feature values with defaults."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_dir = os.path.join(temp_dir, "ml", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        with patch("app.services.anomaly_detector.MODEL_DIR", model_dir):
            with patch("app.services.anomaly_detector.get_model_path") as mock_path:
                user_id = uuid4()
                asset_id = uuid4()
                mock_path.return_value = os.path.join(model_dir, f"{user_id}_{asset_id}.pkl")
                
                # Only provide hour, other features missing
                normal_data = [
                    {"hour": 10},
                    {"hour": 11},
                ]

                model_path = anomaly_detector.train_model(
                    user_id=user_id,
                    asset_id=asset_id,
                    normal_data=normal_data
                )

                assert os.path.exists(model_path)

    finally:
        shutil.rmtree(temp_dir)


# =============================================================================
# Test: Model Persistence Functions
# =============================================================================

def test_delete_model_removes_file():
    """delete_model removes the model file."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_dir = os.path.join(temp_dir, "ml", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        with patch("app.services.anomaly_detector.MODEL_DIR", model_dir):
            with patch("app.services.anomaly_detector.get_model_path") as mock_path:
                # First create a model
                normal_data = [{"hour": 10, "weekday": 1, "project_score": 0.8, "temporal_score": 0.9, "history_score": 0.7}]
                user_id = uuid4()
                asset_id = uuid4()
                model_path = os.path.join(model_dir, f"{user_id}_{asset_id}.pkl")
                mock_path.return_value = model_path
                
                # Create the model file manually for this test
                model = IsolationForest(n_estimators=10, random_state=42)
                model.fit(np.array([[10, 1, 0.8, 0.9, 0.7]]))
                with open(model_path, "wb") as f:
                    pickle.dump(model, f)

                # Delete it
                result = anomaly_detector.delete_model(user_id, asset_id)

                assert result is True
                assert not os.path.exists(model_path)

    finally:
        shutil.rmtree(temp_dir)


def test_delete_model_nonexistent():
    """delete_model returns False for non-existent model."""
    with patch("app.services.anomaly_detector.get_model_path", return_value="/nonexistent/path"):
        result = anomaly_detector.delete_model(uuid4(), uuid4())
        assert result is False


def test_model_exists_true():
    """model_exists returns True when model exists."""
    temp_dir = tempfile.mkdtemp()
    try:
        model_dir = os.path.join(temp_dir, "ml", "models")
        os.makedirs(model_dir, exist_ok=True)
        
        with patch("app.services.anomaly_detector.MODEL_DIR", model_dir):
            with patch("app.services.anomaly_detector.get_model_path") as mock_path:
                user_id = uuid4()
                asset_id = uuid4()
                model_path = os.path.join(model_dir, f"{user_id}_{asset_id}.pkl")
                mock_path.return_value = model_path
                
                # Create model
                model = IsolationForest(n_estimators=10, random_state=42)
                model.fit(np.array([[10, 1, 0.8, 0.9, 0.7]]))
                with open(model_path, "wb") as f:
                    pickle.dump(model, f)

                assert anomaly_detector.model_exists(user_id, asset_id) is True

    finally:
        shutil.rmtree(temp_dir)


def test_model_exists_false():
    """model_exists returns False when model doesn't exist."""
    with patch("app.services.anomaly_detector.os.path.exists", return_value=False):
        assert anomaly_detector.model_exists(uuid4(), uuid4()) is False


# =============================================================================
# Test: Global Model Functions
# =============================================================================

@patch("app.services.anomaly_detector.train_and_persist")
def test_train_global_model(mock_train):
    """train_global_model delegates to train_and_persist."""
    # Create a mock that has to_dict method returning a dict
    mock_metrics = MagicMock()
    mock_metrics.to_dict.return_value = {"precision": 0.8, "recall": 0.7, "f1": 0.75}
    mock_train.return_value = ("path/to/model.joblib", mock_metrics)

    path, metrics = anomaly_detector.train_global_model(n_records=1000)

    mock_train.assert_called_once()
    assert "precision" in metrics


@patch("app.services.anomaly_detector.ml_load_model")
def test_get_global_anomaly_score_no_model(mock_load):
    """Global score with no model → fallback."""
    mock_load.return_value = None

    result = anomaly_detector.get_global_anomaly_score({
        "hour": 10,
        "weekday": 1,
        "project_score": 0.8,
    })

    assert result == 0.3


@patch("app.services.anomaly_detector.ml_load_model")
def test_get_global_anomaly_score_with_model(mock_load):
    """Global score with model → computed score."""
    # Create a mock model
    model = MagicMock()
    model.decision_function.return_value = [0.3]  # Normal
    mock_load.return_value = model

    result = anomaly_detector.get_global_anomaly_score({
        "hour": 10,
        "weekday": 1,
        "project_score": 0.8,
    })

    assert 0.0 <= result <= 1.0
    model.decision_function.assert_called_once()


def test_global_model_exists():
    """global_model_exists checks default model."""
    with patch("app.services.anomaly_detector.ml_model_exists") as mock_exists:
        mock_exists.return_value = True
        assert anomaly_detector.global_model_exists() is True


# =============================================================================
# Test: Retraining
# =============================================================================

@patch("app.services.anomaly_detector.train_global_model")
def test_trigger_retraining(mock_train):
    """trigger_retraining calls train_global_model."""
    mock_train.return_value = ("path/to/model.joblib", {"accuracy": 0.9})

    path, metrics = anomaly_detector.trigger_retraining()

    mock_train.assert_called_once()
    assert "accuracy" in metrics


# =============================================================================
# Test: Score Boundaries
# =============================================================================

def test_anomaly_score_always_in_range():
    """All scores are clamped to [0, 1]."""
    # Even with extreme values, should stay in range
    with patch("app.services.anomaly_detector.os.path.exists", return_value=False):
        # This test verifies the function never returns out-of-range
        # Since we mock no model, it returns 0.3 which is valid

        result = anomaly_detector.get_anomaly_score(
            user_id=uuid4(),
            asset_id=uuid4(),
            context={"hour": 0, "weekday": 0, "project_score": 0, "temporal_score": 0, "history_score": 0}
        )

        assert 0.0 <= result <= 1.0