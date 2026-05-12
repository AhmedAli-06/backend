from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field


# --- Auth Schemas ---
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=128)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: "AuthUserResponse"

class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(..., min_length=1, max_length=255)
    tenant_id: UUID

class AuthUserResponse(BaseModel):
    id: UUID
    email: str
    full_name: str
    tenant_id: UUID
    is_active: bool
    is_superuser: bool
    roles: list[str] = []
    model_config = ConfigDict(from_attributes=True)

# --- Tenant Schemas ---
class TenantResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    industry: str | None
    subscription_tier: str
    is_active: bool
    onboarding_status: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    slug: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-z0-9-]+$")
    industry: str | None = None

# --- Asset Schemas ---
class AssetResponse(BaseModel):
    id: UUID
    name: str
    asset_type: str
    category: str | None
    location: str | None
    criticality: str
    is_monitored: bool
    alert_threshold: float
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

# --- Access Event Schemas ---
class AccessEventResponse(BaseModel):
    id: UUID
    user_id: UUID | None
    asset_id: UUID
    event_type: str
    occurred_at: datetime
    trust_score: float | None
    decision: str | None
    decision_reason: str | None
    model_config = ConfigDict(from_attributes=True)

# --- Alert Schemas ---
class AlertResponse(BaseModel):
    id: UUID
    severity: str
    alert_type: str
    title: str
    status: str
    trust_score_at_trigger: float | None
    triggered_at: datetime
    model_config = ConfigDict(from_attributes=True)

# --- Dashboard ---
class DashboardStats(BaseModel):
    total_assets: int
    active_sessions: int
    open_alerts: int
    avg_trust_score: float
    events_today: int


# --- Alert Management ---
class AlertUpdate(BaseModel):
    status: str
    resolution_notes: str | None = None


# --- Session ---
class SessionResponse(BaseModel):
    id: UUID
    user_id: UUID | None
    asset_id: UUID
    started_at: datetime
    ended_at: datetime | None
    duration_seconds: int | None
    status: str
    avg_trust_score: float | None
    min_trust_score: float | None
    alert_count: int
    model_config = ConfigDict(from_attributes=True)


class RevokeResponse(BaseModel):
    session_id: UUID
    status: str
    revoked_at: datetime
    reason: str


# --- Tenant Config ---
class TenantConfigResponse(BaseModel):
    weight_identity: float
    weight_temporal: float
    weight_project: float
    weight_role: float
    weight_anomaly: float
    default_alert_threshold: float
    default_revocation_threshold: float
    session_timeout_minutes: int
    model_config = ConfigDict(from_attributes=True)


class TenantConfigUpdate(BaseModel):
    weight_identity: float | None = None
    weight_temporal: float | None = None
    weight_project: float | None = None
    weight_role: float | None = None
    weight_anomaly: float | None = None
    default_alert_threshold: float | None = None
    default_revocation_threshold: float | None = None
    session_timeout_minutes: int | None = None


# --- API Keys ---
class ApiKeyResponse(BaseModel):
    id: UUID
    name: str
    key_prefix: str
    scopes: str | None
    is_active: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scopes: str | None = None
    expires_at: datetime | None = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    raw_key: str


# --- Reports ---
class ReportRequest(BaseModel):
    date_from: datetime | None = None
    date_to: datetime | None = None
    format: str = "json"


# --- Audit ---
class AuditLogResponse(BaseModel):
    id: UUID
    action: str
    resource_type: str | None
    resource_id: str | None
    details: dict | None
    ip_address: str | None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)
