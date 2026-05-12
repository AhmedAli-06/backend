import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow():
    return datetime.now(UTC)


class AccessEvent(Base):
    __tablename__ = "access_events"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"))
    credential_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("credentials.id"))
    session_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("access_sessions.id"))
    event_type: Mapped[str] = mapped_column(String(30), nullable=False)
    event_source: Mapped[str | None] = mapped_column(String(50))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Trust scoring outputs
    trust_score: Mapped[float | None] = mapped_column(Float)
    identity_score: Mapped[float | None] = mapped_column(Float)
    temporal_score: Mapped[float | None] = mapped_column(Float)
    project_score: Mapped[float | None] = mapped_column(Float)
    role_score: Mapped[float | None] = mapped_column(Float)
    anomaly_score: Mapped[float | None] = mapped_column(Float)

    # Decision
    decision: Mapped[str | None] = mapped_column(String(20))
    decision_reason: Mapped[str | None] = mapped_column(Text)
    processing_ms: Mapped[int | None] = mapped_column(Integer)

    # Feature vector
    feature_vector: Mapped[dict | None] = mapped_column(JSONB)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AccessSession(Base):
    __tablename__ = "access_sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="active")
    revocation_reason: Mapped[str | None] = mapped_column(String(100))
    avg_trust_score: Mapped[float | None] = mapped_column(Float)
    min_trust_score: Mapped[float | None] = mapped_column(Float)
    max_anomaly_score: Mapped[float | None] = mapped_column(Float)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Relationships
    user = relationship("User", lazy="selectin")
    asset = relationship("Asset", lazy="selectin")
    events = relationship("AccessEvent", lazy="selectin", foreign_keys=[AccessEvent.session_id])


class TrustScoreHistory(Base):
    __tablename__ = "trust_score_history"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("access_sessions.id"))
    tenant_id: Mapped[uuid.UUID] = mapped_column()
    user_id: Mapped[uuid.UUID] = mapped_column()
    asset_id: Mapped[uuid.UUID] = mapped_column()
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    trust_score: Mapped[float] = mapped_column(Float, nullable=False)
    anomaly_score: Mapped[float] = mapped_column(Float, nullable=False)
    trigger_event: Mapped[str | None] = mapped_column(String(50))
