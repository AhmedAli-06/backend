"""
Test login directly via FastAPI TestClient.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import asyncio

from httpx import ASGITransport, AsyncClient

from app.main import app


async def test():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/auth/login",
            data={"username": "admin@meridian-mfg.com", "password": "ContextShield2025!"},
        )
        print(f"Status: {resp.status_code}")
        print(f"Body: {resp.text}")
        if resp.status_code != 200:
            print(f"Headers: {dict(resp.headers)}")

asyncio.run(test())
