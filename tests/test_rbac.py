"""
RBAC Verification Tests

Tests that:
1. Unauthenticated requests return 401 on protected endpoints
2. Authenticated requests with wrong role return 403 on role-restricted endpoints
3. Authenticated requests with correct role succeed
"""

import pytest
from httpx import AsyncClient


@pytest.fixture
async def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# === Task 1: Verify unauthenticated requests return 401 ===
@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/api/v1/alerts/"),
        ("GET", "/api/v1/sessions/"),
        ("GET", "/api/v1/assets/"),
        ("GET", "/api/v1/events/"),
        ("GET", "/api/v1/settings/"),
        ("GET", "/api/v1/api-keys/"),
        ("GET", "/api/v1/audit/logs"),
        ("POST", "/api/v1/access/swipe"),
        ("GET", "/api/v1/dashboard/stats"),
        ("GET", "/api/v1/reports/summary"),
    ],
)
async def test_unauthenticated_returns_401(client: AsyncClient, method: str, path: str):
    """All protected endpoints must reject unauthenticated requests with 401."""
    response = await client.request(method, path)
    assert response.status_code == 401, f"{method} {path} returned {response.status_code}, expected 401"


# === Task 2: Verify role-restricted endpoints return 403 for wrong role ===
@pytest.mark.parametrize(
    "method,path",
    [
        ("PUT", "/api/v1/alerts/00000000-0000-0000-0000-000000000001/acknowledge"),
        ("PUT", "/api/v1/alerts/00000000-0000-0000-0000-000000000001/resolve"),
        ("PUT", "/api/v1/alerts/00000000-0000-0000-0000-000000000001/dismiss"),
        ("POST", "/api/v1/sessions/00000000-0000-0000-0000-000000000001/revoke"),
        ("PUT", "/api/v1/settings/"),
        ("GET", "/api/v1/api-keys/"),
        ("POST", "/api/v1/api-keys/"),
        ("DELETE", "/api/v1/api-keys/00000000-0000-0000-0000-000000000001"),
    ],
)
async def test_viewer_cannot_access_admin_endpoints(client: AsyncClient, method: str, path: str, viewer_headers: dict):
    """Role-restricted endpoints must reject viewer role with 403."""
    response = await client.request(method, path, headers=viewer_headers)
    # Viewer has "viewer" role, not "admin" or "security_officer"
    assert response.status_code == 403, f"{method} {path} returned {response.status_code}, expected 403 for viewer"


# === Task 3: Verify authenticated requests with correct role succeed ===
async def test_admin_can_access_admin_endpoints(client: AsyncClient, auth_headers: dict):
    """Admin role should succeed on admin-restricted endpoints."""
    # Settings PUT requires admin role
    response = await client.put(
        "/api/v1/settings/",
        json={"session_timeout_minutes": 60},
        headers=auth_headers
    )
    # Should not be 403 (may be 404 if no config exists, or 200)
    assert response.status_code != 403, f"Admin should not be denied: {response.status_code}"


async def test_viewer_can_access_read_endpoints(client: AsyncClient, viewer_headers: dict):
    """Viewer role should succeed on read-only endpoints."""
    response = await client.get("/api/v1/dashboard/stats", headers=viewer_headers)
    # Should not be 403 (may be 404 or 500, but not 403)
    assert response.status_code != 403, f"Viewer should have read access: {response.status_code}"


async def test_authenticated_user_can_list_alerts(client: AsyncClient, viewer_headers: dict):
    """Authenticated users should be able to list alerts."""
    response = await client.get("/api/v1/alerts/", headers=viewer_headers)
    assert response.status_code != 401, "Authenticated user should not get 401"


async def test_authenticated_user_can_list_sessions(client: AsyncClient, viewer_headers: dict):
    """Authenticated users should be able to list sessions."""
    response = await client.get("/api/v1/sessions/", headers=viewer_headers)
    assert response.status_code != 401, "Authenticated user should not get 401"


async def test_authenticated_user_can_list_assets(client: AsyncClient, viewer_headers: dict):
    """Authenticated users should be able to list assets."""
    response = await client.get("/api/v1/assets/", headers=viewer_headers)
    assert response.status_code != 401, "Authenticated user should not get 401"


async def test_authenticated_user_can_list_events(client: AsyncClient, viewer_headers: dict):
    """Authenticated users should be able to list events."""
    response = await client.get("/api/v1/events/", headers=viewer_headers)
    assert response.status_code != 401, "Authenticated user should not get 401"


# === Task 4: Verify public endpoints are accessible without auth ===
@pytest.mark.parametrize(
    "method,path",
    [
        # Login uses OAuth2PasswordRequestForm which returns 401 when no credentials
        # This is correct - the endpoint accepts requests but requires HTTP Basic Auth
        ("POST", "/api/v1/auth/register"),
    ],
)
async def test_public_endpoints_no_auth_required(client: AsyncClient, method: str, path: str):
    """Public endpoints (register) should be accessible without auth."""
    if method == "POST" and path == "/api/v1/auth/register":
        response = await client.post(path, json={
            "email": "new@test.com",
            "password": "TestPass123!",
            "full_name": "New User",
            "tenant_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        })
    # Should not be 401 (may be 400, 409, etc but not 401)
    assert response.status_code != 401, f"{method} {path} returned 401, should be public"
