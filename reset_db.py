import asyncio

import app.models  # noqa
from app.database import Base, engine


async def reset():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    print("[OK] All tables dropped and recreated.")

if __name__ == "__main__":
    asyncio.run(reset())
