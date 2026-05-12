from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models.auth import ApiKey, AuthUser

# API Key header - supports both X-API-Key and Authorization with Bearer
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(UTC) + (expires_delta or timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    result = await db.execute(select(AuthUser).where(AuthUser.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active:
        raise credentials_exception
    return user


async def require_superuser(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
    if not current_user.is_superuser:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Superuser required")
    return current_user


def require_role(role_name: str):
    def role_checker(current_user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if current_user.is_superuser:
            return current_user
        user_roles = [ur.role.name for ur in current_user.roles] if current_user.roles else []
        if role_name not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role_name}' required",
            )
        return current_user
    return role_checker


def has_role(current_user: AuthUser, role_name: str) -> bool:
    if current_user.is_superuser:
        return True
    user_roles = [ur.role.name for ur in current_user.roles] if current_user.roles else []
    return role_name in user_roles


# --- API Key Authentication ---

async def verify_api_key(api_key: str, db: AsyncSession) -> ApiKey | None:
    """Verify an API key and return the ApiKey record if valid."""
    if not api_key or len(api_key) < 10:
        return None

    # Extract prefix from the API key (first 10 chars)
    prefix = api_key[:10]

    # Find all API keys with this prefix
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.key_prefix == prefix,
            ApiKey.is_active,
        )
    )
    api_keys = result.scalars().all()

    # Check each key's hash
    for key_record in api_keys:
        if verify_password(api_key, key_record.key_hash):
            # Check expiration
            if key_record.expires_at and key_record.expires_at < datetime.now(UTC):
                return None
            return key_record

    return None


async def get_current_user_with_api_key(
    request: Request,
    api_key_header: str | None = Depends(API_KEY_HEADER),
    db: AsyncSession = Depends(get_db),
) -> AuthUser:
    """
    Get current user from either JWT token or API key.
    Checks X-API-Key header first, then falls back to JWT.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Check for API key in X-API-Key header
    if api_key_header:
        api_key_record = await verify_api_key(api_key_header, db)
        if api_key_record:
            # Update last_used_at
            api_key_record.last_used_at = datetime.now(UTC)
            await db.commit()

            # Get the user from the tenant (use first admin user as API keys are tenant-scoped)
            result = await db.execute(
                select(AuthUser).where(
                    AuthUser.tenant_id == api_key_record.tenant_id,
                    AuthUser.is_active,
                )
            )
            user = result.scalars().first()
            if user:
                return user

    # Fall back to JWT authentication
    # Try to get token from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
            user_id: str | None = payload.get("sub")
            if user_id is None:
                raise credentials_exception

            result = await db.execute(select(AuthUser).where(AuthUser.id == UUID(user_id)))
            user = result.scalar_one_or_none()
            if user is None or not user.is_active:
                raise credentials_exception
            return user
        except JWTError:
            pass

    raise credentials_exception


def check_api_key_scope(api_key_record: ApiKey, required_scope: str) -> bool:
    """Check if API key has the required scope."""
    if not api_key_record.scopes:
        return False

    scopes = api_key_record.scopes.split(",")
    scopes = [s.strip().lower() for s in scopes]

    # Admin scope grants all access
    if "admin" in scopes:
        return True

    # Check specific scope
    return required_scope.lower() in scopes


def require_api_key_scope(required_scope: str):
    """
    Dependency that requires API key to have a specific scope.
    Must be used with get_current_user_with_api_key.
    Note: This only works when the user was authenticated via API key.
    The current_user object doesn't directly expose the API key record,
    so we store it in request.state for scope checking.
    """
    async def scope_checker(
        request: Request,
        api_key_header: str | None = Depends(API_KEY_HEADER),
        db: AsyncSession = Depends(get_db),
    ) -> AuthUser:
        # If no API key, fall back to regular auth
        if not api_key_header:
            # Check via JWT
            return await get_current_user_with_api_key(request, None, db)

        api_key_record = await verify_api_key(api_key_header, db)
        if not api_key_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key",
            )

        if not check_api_key_scope(api_key_record, required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key scope '{required_scope}' required",
            )

        # Update last_used_at
        api_key_record.last_used_at = datetime.now(UTC)
        await db.commit()

        # Get user
        result = await db.execute(
            select(AuthUser).where(
                AuthUser.tenant_id == api_key_record.tenant_id,
                AuthUser.is_active,
            )
        )
        user = result.scalars().first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found for API key",
            )

        # Store api_key in request state for later reference
        request.state.api_key = api_key_record

        return user

    return scope_checker
