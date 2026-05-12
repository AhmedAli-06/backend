from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.auth import AuthUser
from app.models.tenant import TenantConfig
from app.schemas import TenantConfigResponse, TenantConfigUpdate
from app.security import get_current_user, require_role

router = APIRouter(prefix="/api/v1/settings", tags=["Settings"])


@router.get("/", response_model=TenantConfigResponse)
async def get_settings(
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TenantConfig).where(TenantConfig.tenant_id == current_user.tenant_id)
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Settings not found"})
    return config


@router.put("/", response_model=TenantConfigResponse)
async def update_settings(
    updates: TenantConfigUpdate,
    current_user: AuthUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TenantConfig).where(TenantConfig.tenant_id == current_user.tenant_id)
    )
    config = result.scalar_one_or_none()
    if not config:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Settings not found"})

    update_data = updates.model_dump(exclude_none=True)
    for key, value in update_data.items():
        setattr(config, key, value)

    await db.commit()
    await db.refresh(config)
    return config
