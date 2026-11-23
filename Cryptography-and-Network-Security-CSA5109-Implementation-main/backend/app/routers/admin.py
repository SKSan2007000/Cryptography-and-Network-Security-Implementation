from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, UserRole, AuditLog
from backend.app.schemas.schemas import UserResponse, AuditLogResponse
from backend.app.core.dependencies import require_admin
from backend.app.routers.auth import user_to_response

router = APIRouter(prefix="/api/admin", tags=["Administration"])


class RoleUpdateRequest(BaseModel):
    role: str  # 'admin' or 'user'


class StatusUpdateRequest(BaseModel):
    is_active: bool


@router.get("/users", response_model=List[UserResponse])
def get_all_users(
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin: List all users, profiles and roles."""
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [user_to_response(u, db) for u in users]


@router.put("/users/{user_id}/role")
def update_user_role(
    user_id: str,
    req: RoleUpdateRequest,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin: Grant or revoke admin role."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_role = db.query(UserRole).filter(UserRole.user_id == user.id).first()
    if existing_role:
        existing_role.role = req.role
    else:
        new_role = UserRole(user_id=user.id, role=req.role)
        db.add(new_role)

    audit = AuditLog(
        user_id=admin_user.id,
        event="ROLE_MODIFIED",
        severity="warning",
        action="UPDATE_ROLE",
        metadata={"target_user": user_id, "new_role": req.role}
    )
    db.add(audit)
    db.commit()

    return {"message": f"User role updated to {req.role}"}


@router.put("/users/{user_id}/status")
def update_user_status(
    user_id: str,
    req: StatusUpdateRequest,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin: Activate or suspend user account."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = req.is_active
    profile = db.query(Profile).filter(Profile.id == user.id).first()
    if profile:
        profile.status = "active" if req.is_active else "suspended"

    audit = AuditLog(
        user_id=admin_user.id,
        event="ACCOUNT_STATUS_MODIFIED",
        severity="critical" if not req.is_active else "info",
        action="UPDATE_STATUS",
        metadata={"target_user": user_id, "is_active": req.is_active}
    )
    db.add(audit)
    db.commit()

    return {"message": f"User status updated to {'active' if req.is_active else 'suspended'}"}


@router.get("/audit-logs", response_model=List[AuditLogResponse])
def get_audit_logs(
    limit: int = 100,
    admin_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Admin: Retrieve immutable system audit logs."""
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit).all()
    return logs
