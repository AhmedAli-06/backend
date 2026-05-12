# Backend Python Files Inventory

Generated: 2026-05-10
Scope: All Python files excluding `venv/`, `__pycache__/`, `.pytest_cache/`

## Production Application (`app/`)

### Core (8 files)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/__init__.py` | 7 | Package init — re-exports all models for `import app.models` | Models | main.py, seed.py, reset_db.py |
| `app/main.py` | 83 | FastAPI entry point — lifespan, middleware, router assembly | config, database, all routers, audit middleware | `uvicorn app.main:app` |
| `app/config.py` | 53 | Pydantic Settings for all env vars (DB, JWT, CORS, alerting) | pydantic_settings, functools | database.py, security.py, routers, services |
| `app/database.py` | 31 | SQLAlchemy async engine + session factory + Base class | config, sqlalchemy.ext.asyncio | models, routers, services, security |
| `app/schemas.py` | 185 | All Pydantic request/response models (auth, tenant, asset, alerts, sessions, reports, audit) | pydantic, uuid, datetime | All routers |
| `app/security.py` | 81 | JWT auth: hash/verify passwords, create tokens, dependency injection for current_user/roles | jose, passlib, fastapi, sqlalchemy | All routers |
| `app/seed.py` | 202 | Database seed script — creates demo tenant, users, assets, events, alerts | models, security, services | `python -m app.seed` |
| `app/__init__.py` | — | Package marker | — | — |

### Routers (12 files)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/routers/__init__.py` | 5 | Re-exports all routers as named exports | auth, dashboard, assets, events, alerts, sessions, settings, api_keys, reports, audit, ws, access | main.py |
| `app/routers/auth.py` | 290 | Login, register, me endpoints | database, models, schemas, security, config | main.py |
| `app/routers/dashboard.py` | 106 | `/dashboard/stats` aggregated metrics | database, models | main.py |
| `app/routers/assets.py` | 71 | CRUD for physical assets and zones | database, models, schemas, security | main.py |
| `app/routers/events.py` | 32 | Access event history and recent query | database, models, schemas, security | main.py |
| `app/routers/alerts.py` | 61 | Alert list, acknowledge, resolve, dismiss | database, models, schemas, security | main.py |
| `app/routers/sessions.py` | 63 | Active sessions, session detail, revoke | database, models, schemas, security | main.py |
| `app/routers/settings.py` | 46 | Tenant config (trust score weights) get/update | database, models, schemas, security | main.py |
| `app/routers/api_keys.py` | 38 | API key CRUD for programmatic access | database, models, schemas, security | main.py |
| `app/routers/reports.py` | 154 | CSV/JSON export, summary stats, threat scores | database, models, schemas, security | main.py |
| `app/routers/audit.py` | 82 | Audit log query endpoint | database, models, schemas, security | main.py |
| `app/routers/ws.py` | 177 | WebSocket endpoint for live feed streaming | database, models, websocket | main.py |
| `app/routers/access.py` | 39 | Card-swipe simulation endpoint (simulator UI) | database, models, schemas, security | main.py |

### Models (7 files)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/models/__init__.py` | 7 | Re-exports all models from submodules | all models | seed.py, reset_db.py, main.py |
| `app/models/tenant.py` | 64 | Tenant (organization) + TenantConfig (trust weights) | Base, uuid, datetime, relationships | routers, services |
| `app/models/user.py` | 92 | User (person), Credential (RFID badge), Project, ProjectMember, AssetProject | Base, uuid, datetime, relationships | routers, services |
| `app/models/asset.py` | 69 | Asset (physical machine), AssetZone | Base, uuid, datetime, relationships | routers, services |
| `app/models/auth.py` | 20 | AuthUser (login identity), Role, UserRole, ApiKey | Base, uuid, datetime, relationships | routers, security |
| `app/models/alert.py` | 54 | Alert, Incident, IncidentTimeline, AnomalyScore, BaselineModel, ModelFeedback | Base, uuid, datetime, JSONB | routers, services |
| `app/models/audit.py` | 45 | AuditLog for all API mutations | Base, uuid, datetime, JSONB | routers |
| `app/models/access.py` | 40 | AccessEvent (swipe record), AccessSession, TrustScoreHistory | Base, uuid, datetime, JSONB | routers, services |

### Services (8 files)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/services/__init__.py` | 7 | Re-exports service APIs | alert_service, anomaly_detector, baseline_service, context_fusion, ghost_access, insider_threat, trust_engine | seed.py, main.py |
| `app/services/alert_service.py` | 211 | Alert creation with email notification via Resend API | models | routers |
| `app/services/anomaly_detector.py` | 141 | Isolation Forest model inference for anomaly scoring | sklearn, baseline_service | trust_engine, insider_threat |
| `app/services/baseline_service.py` | 95 | Baseline statistics computation and model persistence | models, sqlalchemy | anomaly_detector, context_fusion |
| `app/services/context_fusion.py` | 192 | Project-based access context enrichment | models, baseline_service | trust_engine |
| `app/services/ghost_access.py` | 187 | Ghost (uncredentialed) access detection logic | models | insider_threat |
| `app/services/insider_threat.py` | 195 | Periodic user threat score aggregation + weekly scheduler job | models | main.py (lifespan) |
| `app/services/trust_engine.py` | 172 | Core trust score evaluation engine (0-100) with weighted components | dataclasses | seed.py, access.py |

### Middleware (1 file)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/middleware/__init__.py` | 3 | Package init | — | — |
| `app/middleware/audit.py` | 96 | AuditMiddleware — logs all HTTP requests to AuditLog | database, models, hmac | main.py |

### ML Pipeline (3 files)

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `app/ml/__init__.py` | 3 | Re-exports public ML functions | generate_data, train | internal |
| `app/ml/generate_data.py` | 87 | Synthetic training data generation for Isolation Forest | numpy, pandas | train.py, __init__ |
| `app/ml/train.py` | 131 | Model training + persistence to `ml/models/` | sklearn, uuid, generate_data | admin CLI |

---

## Root-Level Scripts

| File | Lines | Purpose | Imports | Used By |
|------|-------|---------|---------|---------|
| `reset_db.py` | 12 | Utility: drop and recreate all DB tables | database, models | `python reset_db.py` |
| `test_api.py` | 24 | Debug script: test login via FastAPI test client | httpx, main | Manual test |
| `test_login.py` | 18 | Debug script: verify admin user in DB | database, models, security | Manual test |

**Note:** These root-level test files should be moved to `tests/`.

---

## Test Suite (`tests/`)

| File | Lines | Purpose | Imports |
|------|-------|---------|---------|
| `tests/__init__.py` | 3 | Package init | — |
| `tests/conftest.py` | 94 | Shared pytest fixtures (DB, auth headers) | database, models, security |
| `tests/test_api.py` | 129 | Integration tests for API endpoints | conftest, httpx, main |
| `tests/test_trust_engine.py` | 82 | Unit tests for TrustScoreEngine evaluation | conftest |

---

## Convention Issues Identified

### Import Ordering
- Most files follow approximate stdlib → third-party → local ordering, but **not enforced**.
- `app/middleware/audit.py` has a mix: `import hashlib, hmac, json, time, uuid` (stdlib) on same line as `from uuid import UUID` (redundant).
- Several model files have `import uuid` and `from uuid import UUID` simultaneously.

### Tooling Needed
- No `ruff.toml` or `isort.cfg` to enforce consistent import ordering.
- No pre-commit hooks configured.

### Recommended Actions
1. Add `ruff.toml` with isort rules (planned in DEAD_CODE.md).
2. Fix redundant `import uuid` + `from uuid import UUID` across model files.

---

## Dependency Graph (Router → Model → Database)

```
main.py
  ├── config.py ← database.py, security.py
  ├── database.py
  ├── audit middleware
  ├── auth router → models.auth, schemas, security
  ├── dashboard router → models.asset, models.access, models.alert
  ├── assets router → models.asset
  ├── events router → models.access
  ├── alerts router → models.alert
  ├── sessions router → models.access
  ├── settings router → models.tenant
  ├── api_keys router → models.auth
  ├── reports router → models.access, models.alert, models.user
  ├── audit router → models.audit
  ├── ws router → models.access, models.alert, models.user
  └── access router → models.user, models.asset

services/trust_engine.py ← models.access
services/insider_threat.py ← models.user, models.access
services/context_fusion.py ← models.asset, models.user, services.baseline_service
services/anomaly_detector.py ← services.baseline_service
services/baseline_service.py ← models.access
services/alert_service.py ← models.alert
services/ghost_access.py ← models.access, models.user
```