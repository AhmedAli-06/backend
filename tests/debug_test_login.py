import asyncio

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.auth import AuthUser
from app.security import verify_password


async def test():
    async with AsyncSessionLocal() as db:
        r = await db.execute(select(AuthUser).where(AuthUser.email == "admin@meridian-mfg.com"))
        u = r.scalar_one_or_none()
        print(f"User: {u}")
        if u:
            print(f"ID: {u.id}")
            print(f"Tenant: {u.tenant_id}")
            print(f"Active: {u.is_active}")
            print(f"Pwd OK: {verify_password('ContextShield2025!', u.password_hash)}")

asyncio.run(test())
