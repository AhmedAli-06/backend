import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.auth import ApiKey, AuthUser
from app.schemas import ApiKeyCreate, ApiKeyCreatedResponse, ApiKeyResponse
from app.security import hash_password, require_role

router = APIRouter(prefix="/api/v1/api-keys", tags=["API Keys"])


def generate_api_key() -> tuple[str, str, str]:
    raw = f"cs_{secrets.token_hex(24)}"
    prefix = raw[:10]
    hashed = hash_password(raw)
    return raw, prefix, hashed


@router.get("/", response_model=list[ApiKeyResponse])
async def list_api_keys(
    current_user: AuthUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApiKey).where(ApiKey.tenant_id == current_user.tenant_id)
    )
    return result.scalars().all()


@router.post("/", response_model=ApiKeyCreatedResponse, status_code=201)
async def create_api_key(
    req: ApiKeyCreate,
    current_user: AuthUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    raw_key, prefix, key_hash = generate_api_key()
    api_key = ApiKey(
        tenant_id=current_user.tenant_id,
        name=req.name,
        key_hash=key_hash,
        key_prefix=prefix,
        scopes=req.scopes,
        expires_at=req.expires_at,
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    return ApiKeyCreatedResponse(
        id=api_key.id,
        name=api_key.name,
        key_prefix=api_key.key_prefix,
        scopes=api_key.scopes,
        is_active=api_key.is_active,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        created_at=api_key.created_at,
        raw_key=raw_key,
    )


@router.delete("/{key_id}", status_code=204)
async def delete_api_key(
    key_id: uuid.UUID,
    current_user: AuthUser = Depends(require_role("admin")),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.tenant_id == current_user.tenant_id,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "API key not found"})
    key.is_active = False
    await db.commit()
