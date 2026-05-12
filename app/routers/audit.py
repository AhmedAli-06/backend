from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.audit import verify_audit_entry
from app.models.audit import AuditLog
from app.models.auth import AuthUser
from app.schemas import AuditLogResponse
from app.security import get_current_user

router = APIRouter(prefix="/api/v1/audit", tags=["Audit"])


class VerifyAuditRequest(BaseModel):
    log_id: UUID
    signature: str


@router.get("/logs", response_model=list[AuditLogResponse])
async def list_audit_logs(
    limit: int = 100,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(AuditLog)
        .where(AuditLog.tenant_id == current_user.tenant_id)
        .order_by(desc(AuditLog.created_at))
        .limit(limit)
    )
    return result.scalars().all()


@router.post("/verify")
async def verify_audit_entry_endpoint(
    body: VerifyAuditRequest,
    current_user: AuthUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    log = await db.get(AuditLog, body.log_id)
    if log is None:
        raise HTTPException(status_code=404, detail={"code": "NOT_FOUND", "detail": "Audit log not found"})
    if log.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "detail": "Access denied"})

    try:
        details = dict(log.details or {})
        stored_hmac = details.pop("_hmac", None)
        if stored_hmac is None:
            raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "detail": "Log has no integrity signature"})

        signed = {
            "id": str(log.id),
            "tenant_id": str(log.tenant_id),
            "auth_user_id": str(log.auth_user_id) if log.auth_user_id else None,
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": log.resource_id,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": details,
        }

        is_valid = verify_audit_entry(signed, body.signature)
        return {"valid": is_valid}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail={"code": "VALIDATION_ERROR", "detail": "Verification failed"})
