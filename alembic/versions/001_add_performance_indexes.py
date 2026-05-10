"""Add performance indexes for access_events, alerts, sessions tables.

Revision ID: 001_add_performance_indexes
Revises: 
Create Date: 2026-05-10

Adds composite indexes to support high-frequency query patterns:
- access_events: (tenant_id, occurred_at DESC) for time-range queries
- access_events: (user_id, occurred_at DESC) for user baseline computation
- access_events: (asset_id, occurred_at DESC) for asset baseline computation
- alerts: (tenant_id, status, triggered_at DESC) for status-filtered lists
- access_sessions: (tenant_id, status) for active session filtering
"""

from alembic import op
import sqlalchemy as sa


revision = "001_add_performance_indexes"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Access events time-series index
    op.create_index(
        "ix_access_events_tenant_occurred",
        "access_events",
        ["tenant_id", "occurred_at"],
        unique=False,
    )

    # User access history for baseline computation
    op.create_index(
        "ix_access_events_user_time",
        "access_events",
        ["user_id", "occurred_at"],
        unique=False,
    )

    # Asset access history for baseline computation
    op.create_index(
        "ix_access_events_asset_time",
        "access_events",
        ["asset_id", "occurred_at"],
        unique=False,
    )

    # Alerts status-filtered index
    op.create_index(
        "ix_alerts_tenant_status_triggered",
        "alerts",
        ["tenant_id", "status", "triggered_at"],
        unique=False,
    )

    # Session status filtering index
    op.create_index(
        "ix_access_sessions_tenant_status",
        "access_sessions",
        ["tenant_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_access_events_tenant_occurred", "access_events")
    op.drop_index("ix_access_events_user_time", "access_events")
    op.drop_index("ix_access_events_asset_time", "access_events")
    op.drop_index("ix_alerts_tenant_status_triggered", "alerts")
    op.drop_index("ix_access_sessions_tenant_status", "access_sessions")