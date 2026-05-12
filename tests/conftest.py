import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

from app.database import Base, get_db
from app.main import app
from app.models.auth import AuthUser, Role, UserRole
from app.models.tenant import Tenant, TenantConfig
from app.security import create_access_token, hash_password


# Make JSONB work with SQLite for testing
@compiles(JSONB)
def compile_jsonb_sqlite(type_, compiler, **kw):
    return compiler.visit_JSON(type_, **kw)

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"
TENANT_ID = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


@pytest.fixture
async def engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def db_session(engine):
    session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)()
    try:
        yield session
    finally:
        await session.close()


@pytest.fixture
async def client(db_session):
    async def override_get_db():
        yield db_session
    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
async def seed_tenant(db_session):
    tenant = Tenant(
        id=TENANT_ID, name="Test Corp", slug="test-corp",
        industry="manufacturing", subscription_tier="pilot",
        onboarding_status="active",
    )
    db_session.add(tenant)
    db_session.add(TenantConfig(tenant_id=TENANT_ID))
    await db_session.commit()
    return tenant


@pytest.fixture
async def seed_roles(db_session, seed_tenant):
    roles = {}
    for rname in ["admin", "security_officer", "supervisor", "operator", "viewer"]:
        r = Role(tenant_id=TENANT_ID, name=rname, is_system=True)
        db_session.add(r)
        roles[rname] = r
    await db_session.commit()
    return roles


@pytest.fixture
async def admin_user(db_session, seed_tenant, seed_roles):
    user = AuthUser(
        tenant_id=TENANT_ID, email="admin@test.com",
        password_hash=hash_password("TestPass123!"),
        full_name="Test Admin", is_superuser=True,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(auth_user_id=user.id, role_id=seed_roles["admin"].id))
    await db_session.commit()
    return user


@pytest.fixture
async def viewer_user(db_session, seed_tenant, seed_roles):
    user = AuthUser(
        tenant_id=TENANT_ID, email="viewer@test.com",
        password_hash=hash_password("TestPass123!"),
        full_name="Test Viewer", is_superuser=False,
    )
    db_session.add(user)
    await db_session.flush()
    db_session.add(UserRole(auth_user_id=user.id, role_id=seed_roles["viewer"].id))
    await db_session.commit()
    return user


@pytest.fixture
async def admin_token(admin_user):
    return create_access_token({"sub": str(admin_user.id), "tenant_id": str(admin_user.tenant_id)})


@pytest.fixture
async def viewer_token(viewer_user):
    return create_access_token({"sub": str(viewer_user.id), "tenant_id": str(viewer_user.tenant_id)})


@pytest.fixture
async def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}
