"""Demo mode router — seed data endpoint for demo/trial users."""
import asyncio
from fastapi import APIRouter, Depends, HTTPException
from app.models.auth import AuthUser
from app.security import require_role
from app.config import get_settings

router = APIRouter(prefix="/api/v1/demo", tags=["Demo"])


@router.post("/seed")
async def seed_demo_data(current_user: AuthUser = Depends(require_role("admin"))):
    if not get_settings().DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo mode is disabled")
    from app.seed import seed
    loop = asyncio.get_event_loop()
    await seed()
    return {"status": "ok", "message": "Demo data seeded successfully"}
