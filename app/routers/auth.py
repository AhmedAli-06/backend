from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.auth import AuthUser
from app.schemas import AuthUserResponse, RegisterRequest, TokenResponse
from app.security import create_access_token, get_current_user, hash_password, verify_password

settings = get_settings()
router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuthUser).where(AuthUser.email == form.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "UNAUTHORIZED", "detail": "Invalid credentials"}
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "FORBIDDEN", "detail": "Account disabled"}
        )
    if user.locked_until and user.locked_until > datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail={"code": "FORBIDDEN", "detail": "Account temporarily locked"}
        )

    user.failed_login_count = 0
    user.last_login_at = datetime.now(UTC)
    await db.commit()

    roles = [ur.role.name for ur in user.roles] if user.roles else []
    token = create_access_token({"sub": str(user.id), "tenant_id": str(user.tenant_id), "roles": roles})
    return TokenResponse(
        access_token=token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=AuthUserResponse(
            id=user.id, email=user.email, full_name=user.full_name,
            tenant_id=user.tenant_id, is_active=user.is_active,
            is_superuser=user.is_superuser, roles=roles,
        ),
    )


@router.post("/register", response_model=AuthUserResponse, status_code=201)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(AuthUser).where(AuthUser.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "VALIDATION_ERROR", "detail": "Email already registered"}
        )

    user = AuthUser(
        email=req.email,
        password_hash=hash_password(req.password),
        full_name=req.full_name,
        tenant_id=req.tenant_id,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return AuthUserResponse(
        id=user.id, email=user.email, full_name=user.full_name,
        tenant_id=user.tenant_id, is_active=user.is_active,
        is_superuser=user.is_superuser, roles=[],
    )


class RefreshTokenRequest(BaseModel):
    token: str


class TokenRefreshResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


@router.get("/me", response_model=AuthUserResponse)
async def get_me(current_user: AuthUser = Depends(get_current_user)):
    roles = [ur.role.name for ur in current_user.roles] if current_user.roles else []
    return AuthUserResponse(
        id=current_user.id, email=current_user.email, full_name=current_user.full_name,
        tenant_id=current_user.tenant_id, is_active=current_user.is_active,
        is_superuser=current_user.is_superuser, roles=roles,
    )


@router.post("/refresh", response_model=TokenRefreshResponse)
async def refresh_token(req: RefreshTokenRequest, db: AsyncSession = Depends(get_db)):
    """Refresh an access token using a valid (not expired) token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"code": "UNAUTHORIZED", "detail": "Invalid refresh token"},
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            req.token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str | None = payload.get("sub")
        roles: list[str] = payload.get("roles", [])
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Verify user still exists and is active
    result = await db.execute(select(AuthUser).where(AuthUser.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception

    new_token = create_access_token({
        "sub": str(user.id),
        "tenant_id": str(user.tenant_id),
        "roles": roles,
    })
    return TokenRefreshResponse(
        access_token=new_token,
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
