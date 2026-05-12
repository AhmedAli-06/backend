"""
Generate synthetic training data for anomaly detection models.

Creates labeled data for training Isolation Forest models per user-asset pair.
Supports realistic multi-factor scenarios including:
- Normal patterns (work hours, assigned projects)
- Unusual hours (2am access)
- Impossible travel (access from multiple locations in short time)
- Role misuse (low clearance accessing high-security assets)
- Volume anomalies (100 accesses in 1 hour vs normal 10/day)
- Multi-factor patterns (combining subtle anomalies)
"""

import random
from collections.abc import Generator
from typing import Any

import pandas as pd

# Realistic patterns for insider threat scenarios
TYPICAL_WORK_HOURS = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
UNUSUAL_HOURS = [0, 1, 2, 3, 4, 5, 22, 23]
TYPICAL_WEEKDAYS = [0, 1, 2, 3, 4]  # Mon-Fri
UNUSUAL_WEEKDAYS = [5, 6]  # Sat, Sun


def _generate_normal_pattern(
    n_samples: int,
    seed: int | None = None
) -> list[dict[str, Any]]:
    """
    Generate normal access patterns.
    Normal = typical work hours, assigned projects, authorized assets.
    """
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        hour = rng.choice(TYPICAL_WORK_HOURS)
        weekday = rng.choice(TYPICAL_WEEKDAYS)

        # Normal scores: high project assignment, normal temporal patterns
        records.append({
            "hour": hour,
            "weekday": weekday,
            "project_score": rng.uniform(0.7, 1.0),
            "temporal_score": rng.uniform(0.7, 1.0),
            "history_score": rng.uniform(0.6, 1.0),
            "pattern_type": "normal",
            "access_frequency": rng.randint(1, 20),  # accesses per day
            "session_duration_mins": rng.randint(15, 120),
            "location_consistency": rng.uniform(0.8, 1.0),
            "role_match": True,  # authorized for this asset
            "label": 0  # 0 = normal
        })
    return records


def _generate_unusual_hours_anomaly(n_samples: int, seed: int | None = None) -> list[dict[str, Any]]:
    """Generate anomalies: access at unusual hours (2am access to secure area)."""
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        hour = rng.choice(UNUSUAL_HOURS)
        weekday = rng.choice(TYPICAL_WEEKDAYS + UNUSUAL_WEEKDAYS)

        records.append({
            "hour": hour,
            "weekday": weekday,
            "project_score": rng.uniform(0.1, 0.4),
            "temporal_score": rng.uniform(0.1, 0.3),
            "history_score": rng.uniform(0.2, 0.5),
            "pattern_type": "unusual_hours",
            "access_frequency": rng.randint(1, 5),
            "session_duration_mins": rng.randint(5, 30),
            "location_consistency": rng.uniform(0.5, 0.9),
            "role_match": True,
            "label": 1
        })
    return records


def _generate_impossible_travel_anomaly(n_samples: int, seed: int | None = None) -> list[dict[str, Any]]:
    """Generate anomalies: impossible travel (access from two locations in short time)."""
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        # Access from unusual location
        records.append({
            "hour": rng.choice(TYPICAL_WORK_HOURS + UNUSUAL_HOURS),
            "weekday": rng.choice(TYPICAL_WEEKDAYS + UNUSUAL_WEEKDAYS),
            "project_score": rng.uniform(0.4, 0.7),
            "temporal_score": rng.uniform(0.3, 0.6),
            "history_score": rng.uniform(0.4, 0.7),
            "pattern_type": "impossible_travel",
            "access_frequency": rng.randint(5, 30),
            "session_duration_mins": rng.randint(1, 15),
            "location_consistency": rng.uniform(0.0, 0.3),
            "role_match": True,
            "label": 1
        })
    return records


def _generate_role_misuse_anomaly(n_samples: int, seed: int | None = None) -> list[dict[str, Any]]:
    """Generate anomalies: role misuse (low-clearance accessing high-security assets)."""
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        records.append({
            "hour": rng.choice(TYPICAL_WORK_HOURS),
            "weekday": rng.choice(TYPICAL_WEEKDAYS),
            "project_score": rng.uniform(0.1, 0.3),
            "temporal_score": rng.uniform(0.2, 0.5),
            "history_score": rng.uniform(0.3, 0.6),
            "pattern_type": "role_misuse",
            "access_frequency": rng.randint(1, 10),
            "session_duration_mins": rng.randint(5, 45),
            "location_consistency": rng.uniform(0.6, 0.9),
            "role_match": False,  # unauthorized
            "label": 1
        })
    return records


def _generate_volume_anomaly(n_samples: int, seed: int | None = None) -> list[dict[str, Any]]:
    """Generate anomalies: volume anomaly (100 accesses in 1 hour vs normal 10/day)."""
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        records.append({
            "hour": rng.choice(TYPICAL_WORK_HOURS),
            "weekday": rng.choice(TYPICAL_WEEKDAYS),
            "project_score": rng.uniform(0.2, 0.5),
            "temporal_score": rng.uniform(0.3, 0.6),
            "history_score": rng.uniform(0.1, 0.4),
            "pattern_type": "volume_anomaly",
            "access_frequency": rng.randint(50, 200),  # very high
            "session_duration_mins": rng.randint(1, 10),
            "location_consistency": rng.uniform(0.5, 0.9),
            "role_match": True,
            "label": 1
        })
    return records


def _generate_multi_factor_anomaly(n_samples: int, seed: int | None = None) -> list[dict[str, Any]]:
    """Generate anomalies: multi-factor patterns (combining multiple subtle anomalies)."""
    rng = random.Random(seed)

    records = []
    for _ in range(n_samples):
        # Subtle combination: slightly unusual hour, moderate project mismatch, unusual frequency
        records.append({
            "hour": rng.choice([7, 18, 19]),  # slightly early/late
            "weekday": rng.choice(TYPICAL_WEEKDAYS),
            "project_score": rng.uniform(0.4, 0.6),
            "temporal_score": rng.uniform(0.4, 0.6),
            "history_score": rng.uniform(0.4, 0.6),
            "pattern_type": "multi_factor",
            "access_frequency": rng.randint(30, 60),
            "session_duration_mins": rng.randint(10, 30),
            "location_consistency": rng.uniform(0.4, 0.7),
            "role_match": rng.choice([True, False]),
            "label": 1
        })
    return records


def generate_training_data(
    user_id: str,
    asset_id: str,
    n_normal: int = 200,
    n_anomaly: int = 30
) -> pd.DataFrame:
    """
    Generate synthetic access event data for training.

    Generates realistic insider threat scenarios:
    - Normal patterns: work hours, assigned projects
    - Unusual hours: after midnight access
    - Impossible travel: simultaneous location access
    - Role misuse: unauthorized asset access
    - Volume anomalies: burst access patterns
    - Multi-factor: subtle combination patterns

    Args:
        user_id: User identifier
        asset_id: Asset identifier
        n_normal: Number of normal access patterns
        n_anomaly: Number of anomalous access patterns

    Returns:
        DataFrame with features and label column
    """
    # Combine normal and anomaly patterns
    records = []

    # Normal patterns (~85% of anomalies distributed across types)
    normal_records = _generate_normal_pattern(n_normal, seed=42)
    records.extend(normal_records)

    # Anomaly patterns (~15% distributed across types)
    anomaly_types = [
        (_generate_unusual_hours_anomaly, 0.25),
        (_generate_impossible_travel_anomaly, 0.20),
        (_generate_role_misuse_anomaly, 0.25),
        (_generate_volume_anomaly, 0.15),
        (_generate_multi_factor_anomaly, 0.15),
    ]

    for generator, proportion in anomaly_types:
        n_this_type = int(n_anomaly * proportion)
        anomaly_records = generator(n_this_type, seed=random.randint(0, 9999))
        records.extend(anomaly_records)

    # Add user_id and asset_id to all records
    df = pd.DataFrame(records)
    df.insert(0, "user_id", user_id)
    df.insert(1, "asset_id", asset_id)

    return df


def generate_batch_data(
    user_asset_pairs: list[tuple[str, str]],
    n_normal_per_pair: int = 200,
    n_anomaly_per_pair: int = 30
) -> Generator[pd.DataFrame, None, None]:
    """
    Generate training data for multiple user-asset pairs.

    Args:
        user_asset_pairs: List of (user_id, asset_id) tuples
        n_normal_per_pair: Normal samples per pair
        n_anomaly_per_pair: Anomaly samples per pair

    Yields:
        DataFrame for each user-asset pair
    """
    for user_id, asset_id in user_asset_pairs:
        yield generate_training_data(
            user_id, asset_id,
            n_normal=n_normal_per_pair,
            n_anomaly=n_anomaly_per_pair
        )


def generate_large_dataset(
    n_records: int = 1000,
    n_users: int = 10,
    n_assets: int = 20
) -> pd.DataFrame:
    """
    Generate a large synthetic dataset for model training.

    Args:
        n_records: Target total number of records
        n_users: Number of distinct users
        n_assets: Number of distinct assets

    Returns:
        DataFrame with features and label column
    """
    all_records = []

    # Calculate records per user-asset pair
    n_pairs = n_users * n_assets
    records_per_pair = max(n_records // n_pairs, 100)

    for user_idx in range(n_users):
        user_id = f"synthetic-user-{user_idx:03d}"
        for asset_idx in range(n_assets):
            asset_id = f"synthetic-asset-{asset_idx:03d}"

            df = generate_training_data(
                user_id, asset_id,
                n_normal=int(records_per_pair * 0.85),
                n_anomaly=int(records_per_pair * 0.15)
            )
            all_records.append(df)

    combined = pd.concat(all_records, ignore_index=True)
    return combined


def get_feature_columns() -> list[str]:
    """Return the feature column names used for training."""
    return ["hour", "weekday", "project_score", "temporal_score", "history_score"]


def get_label_column() -> str:
    """Return the label column name."""
    return "label"


def get_extended_features() -> list[str]:
    """Return all available feature columns for advanced training."""
    return [
        "hour", "weekday", "project_score", "temporal_score", "history_score",
        "access_frequency", "session_duration_mins", "location_consistency", "role_match"
    ]
