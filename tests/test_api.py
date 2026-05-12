import pytest

pytestmark = pytest.mark.asyncio

class TestHealth:
    async def test_health_endpoint(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "contextshield"

class TestAuth:
    async def test_login_success(self, client, admin_user):
        resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin@test.com", "password": "TestPass123!"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    async def test_login_invalid_password(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin@test.com", "password": "wrong"},
        )
        assert resp.status_code == 401

    async def test_login_nonexistent_user(self, client):
        resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "nobody@test.com", "password": "TestPass123!"},
        )
        assert resp.status_code == 401

    async def test_get_me(self, client, auth_headers):
        resp = await client.get("/api/v1/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "admin@test.com"

    async def test_get_me_unauthorized(self, client):
        resp = await client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    async def test_get_me_invalid_token(self, client):
        resp = await client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid"})
        assert resp.status_code == 401

class TestAssets:
    async def test_list_assets_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/assets/", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_get_asset_not_found(self, client, auth_headers):
        resp = await client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000", headers=auth_headers)
        assert resp.status_code == 404

class TestEvents:
    async def test_list_events_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/events/", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_recent_events_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/events/recent", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

class TestAlerts:
    async def test_list_alerts_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/alerts/", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_alerts_filtered(self, client, auth_headers):
        resp = await client.get("/api/v1/alerts/?status=open", headers=auth_headers)
        assert resp.status_code == 200

class TestDashboard:
    async def test_dashboard_stats(self, client, auth_headers):
        resp = await client.get("/api/v1/dashboard/stats", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_assets" in data
        assert "active_sessions" in data
        assert "open_alerts" in data
        assert "avg_trust_score" in data
        assert "events_today" in data


class TestSessions:
    async def test_list_sessions_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/sessions/", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_active_sessions_empty(self, client, auth_headers):
        resp = await client.get("/api/v1/sessions/active", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_get_session_not_found(self, client, auth_headers):
        resp = await client.get("/api/v1/sessions/00000000-0000-0000-0000-000000000000", headers=auth_headers)
        assert resp.status_code == 404


class TestSettings:
    async def test_get_settings(self, client, auth_headers, seed_tenant):
        resp = await client.get("/api/v1/settings/", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "weight_identity" in data
        assert data["weight_identity"] == 0.25

    async def test_update_settings(self, client, auth_headers, seed_tenant):
        resp = await client.put("/api/v1/settings/", json={"weight_identity": 0.5}, headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["weight_identity"] == 0.5


class TestAlertsManagement:
    async def test_get_alert_not_found(self, client, auth_headers):
        resp = await client.get("/api/v1/alerts/00000000-0000-0000-0000-000000000000", headers=auth_headers)
        assert resp.status_code == 404

    async def test_acknowledge_not_found(self, client, auth_headers):
        resp = await client.put("/api/v1/alerts/00000000-0000-0000-0000-000000000000/acknowledge", headers=auth_headers)
        assert resp.status_code == 404

    async def test_resolve_not_found(self, client, auth_headers):
        resp = await client.put("/api/v1/alerts/00000000-0000-0000-0000-000000000000/resolve", json={"status": "resolved"}, headers=auth_headers)
        assert resp.status_code == 404


class TestApiKeys:
    async def test_list_api_keys(self, client, auth_headers):
        resp = await client.get("/api/v1/api-keys/", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_create_api_key(self, client, auth_headers):
        resp = await client.post("/api/v1/api-keys/", json={"name": "test-key"}, headers=auth_headers)
        assert resp.status_code == 201
        data = resp.json()
        assert "raw_key" in data
        assert data["name"] == "test-key"


class TestReports:
    async def test_export_json(self, client, auth_headers):
        resp = await client.get("/api/v1/reports/events/json?hours=24", headers=auth_headers)
        assert resp.status_code == 200

    async def test_export_csv(self, client, auth_headers):
        resp = await client.get("/api/v1/reports/events/csv?hours=24", headers=auth_headers)
        assert resp.status_code == 200
