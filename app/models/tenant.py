import uuid
from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow():
    return datetime.now(UTC)


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    industry: Mapped[str | None] = mapped_column(String(100))
    deployment_mode: Mapped[str] = mapped_column(String(20), default="cloud")
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")
    subscription_tier: Mapped[str] = mapped_column(String(20), default="pilot")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    onboarding_status: Mapped[str] = mapped_column(String(30), default="pending")
    baseline_ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    # Relationships
    users = relationship("User", back_populates="tenant", lazy="selectin")
    assets = relationship("Asset", back_populates="tenant", lazy="selectin")
    config = relationship("TenantConfig", back_populates="tenant", uselist=False, lazy="selectin")


class TenantConfig(Base):
    __tablename__ = "tenant_config"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), unique=True)

    # Trust score weights
    weight_identity: Mapped[float] = mapped_column(Float, default=0.25)
    weight_temporal: Mapped[float] = mapped_column(Float, default=0.20)
    weight_project: Mapped[float] = mapped_column(Float, default=0.25)
    weight_role: Mapped[float] = mapped_column(Float, default=0.15)
    weight_anomaly: Mapped[float] = mapped_column(Float, default=0.15)

    # Thresholds
    default_alert_threshold: Mapped[float] = mapped_column(Float, default=0.4)
    default_revocation_threshold: Mapped[float] = mapped_column(Float, default=0.2)

    # Baseline
    baseline_training_days: Mapped[int] = mapped_column(Integer, default=30)
    model_retrain_interval_days: Mapped[int] = mapped_column(Integer, default=7)

    # Session
    session_timeout_minutes: Mapped[int] = mapped_column(Integer, default=480)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    tenant = relationship("Tenant", back_populates="config")
