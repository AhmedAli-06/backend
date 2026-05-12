"""
Synthetic Data Generator Service.

Generates realistic multi-factor training data for ML-based anomaly detection.
Supports insider threat scenarios including:
- Normal patterns (work hours, assigned projects)
- Unusual hours (2am access to secure area)
- Impossible travel (access from two locations in short time)
- Role misuse (low-clearance accessing high-security assets)
- Volume anomalies (burst access patterns)
- Multi-factor patterns (subtle combination anomalies)

Uses the ML module's generate_data.py for core generation logic.
"""

from app.ml.generate_data import (
    generate_batch_data,
    generate_large_dataset,
    generate_training_data,
    get_extended_features,
    get_feature_columns,
    get_label_column,
)

__all__ = [
    "generate_training_data",
    "generate_large_dataset",
    "generate_batch_data",
    "get_feature_columns",
    "get_extended_features",
    "get_label_column",
]
