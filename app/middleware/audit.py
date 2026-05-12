import hashlib
import hmac
import json
import time
import uuid
from uuid import UUID

from fastapi import Request, Response
from jose import jwt
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings
from app.database import AsyncSessionLocal
from app.models.audit import AuditLog


def _hmac_secret() -> bytes:
    return get_settings().HMAC_SECRET.encode()


def sign_audit_entry(entry: dict) -> str:
    message = json.dumps(entry, sort_keys=True, default=str).encode()
    return hmac.new(_hmac_secret(), message, hashlib.sha256).hexdigest()


def verify_audit_entry(entry: dict, signature: str) -> bool:
    expected = sign_audit_entry(entry)
    return hmac.compare_digest(expected, signature)


def _parse_auth_token(request: Request) -> tuple[UUID | None, UUID | None]:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, None
    try:
        payload = jwt.decode(
            auth[7:],
            get_settings().JWT_SECRET_KEY,
            algorithms=[get_settings().JWT_ALGORITHM],
        )
        sub = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        return (
            UUID(sub) if sub else None,
            UUID(tenant_id) if tenant_id else None,
        )
    except Exception:
        return None, None


def _parse_resource_path(path: str) -> tuple[str | None, str | None]:
    parts = path.strip("/").split("/")
    if len(parts) >= 3:
        resource_type = parts[2]
        resource_id = parts[3] if len(parts) > 3 else None
        return resource_type, resource_id
    return None, None


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        if request.method in ("GET", "HEAD", "OPTIONS"):
            return response

        if "/api/v1/" not in request.url.path:
            return response

        try:
            auth_user_id, tenant_id = _parse_auth_token(request)
            if tenant_id is None:
                return response

            resource_type, resource_id = _parse_resource_path(request.url.path)

            entry_id = uuid.uuid4()
            now = time.time()
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")
            details = {
                "status_code": response.status_code,
                "method": request.method,
                "path": request.url.path,
                "timestamp": now,
            }

            signed = {
                "id": str(entry_id),
                "tenant_id": str(tenant_id),
                "auth_user_id": str(auth_user_id) if auth_user_id else None,
                "action": f"{request.method} {request.url.path}",
                "resource_type": resource_type,
                "resource_id": resource_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "details": details,
            }
            details["_hmac"] = sign_audit_entry(signed)

            async with AsyncSessionLocal() as db:
                entry = AuditLog(
                    id=entry_id,
                    tenant_id=tenant_id,
                    auth_user_id=auth_user_id,
                    action=signed["action"],
                    resource_type=resource_type,
                    resource_id=resource_id,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    details=details,
                )
                db.add(entry)
                await db.commit()
        except Exception:
            pass

        return response
