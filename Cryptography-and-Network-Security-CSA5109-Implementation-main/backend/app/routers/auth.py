from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, UserRole, AppSession, AuditLog
from backend.app.schemas.schemas import RegisterRequest, LoginRequest, TokenResponse, UserResponse, ProfileResponse
from backend.app.core.security import hash_password, verify_password, create_access_token
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


def user_to_response(user: User, db: Session) -> UserResponse:
    profile = db.query(Profile).filter(Profile.id == user.id).first()
    roles = [r.role for r in db.query(UserRole).filter(UserRole.user_id == user.id).all()]
    prof_resp = ProfileResponse.model_validate(profile) if profile else None
    return UserResponse(
        id=user.id,
        email=user.email,
        is_active=user.is_active,
        profile=prof_resp,
        roles=roles,
        created_at=user.created_at
    )


@router.post("/register", response_model=TokenResponse)
def register(req: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email.lower()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    # Create User
    hashed = hash_password(req.password)
    user = User(
        email=req.email.lower(),
        hashed_password=hashed,
        is_active=True
    )
    db.add(user)
    db.flush()

    # Create Profile
    profile = Profile(
        id=user.id,
        email=user.email,
        full_name=req.full_name or req.email.split("@")[0],
        organization=req.organization or "Independent",
        trust_score=100,
        trust_status="TRUSTED",
        status="active"
    )
    db.add(profile)

    # Assign default role ('admin' if first user or email contains admin, else 'user')
    user_count = db.query(User).count()
    assigned_role = "admin" if user_count <= 1 or "admin" in req.email.lower() else "user"
    role = UserRole(user_id=user.id, role=assigned_role)
    db.add(role)

    # Log Audit
    audit = AuditLog(
        user_id=user.id,
        event="USER_REGISTERED",
        severity="info",
        ip_address=request.client.host if request.client else "127.0.0.1",
        action="REGISTER",
        metadata={"email": user.email, "role": assigned_role}
    )
    db.add(audit)

    # Create Session
    session_expire = datetime.now(timezone.utc) + timedelta(days=7)
    app_session = AppSession(
        user_id=user.id,
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "browser"),
        expires_at=session_expire
    )
    db.add(app_session)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.id, "email": user.email, "roles": [assigned_role]})
    response.set_cookie(key="access_token", value=token, httponly=True, samesite="lax", max_age=604800)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user_to_response(user, db)
    )


@router.post("/login", response_model=TokenResponse)
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email.lower()).first()
    if not user or not verify_password(req.password, user.hashed_password):
        # Log failed attempt
        audit = AuditLog(
            user_id=user.id if user else None,
            event="LOGIN_FAILED",
            severity="warning",
            ip_address=request.client.host if request.client else "127.0.0.1",
            action="LOGIN",
            metadata={"email": req.email}
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is suspended or deactivated"
        )

    # Roles
    roles = [r.role for r in db.query(UserRole).filter(UserRole.user_id == user.id).all()]
    token = create_access_token({"sub": user.id, "email": user.email, "roles": roles})

    # Record Session
    session_expire = datetime.now(timezone.utc) + timedelta(days=7)
    app_session = AppSession(
        user_id=user.id,
        ip_address=request.client.host if request.client else "127.0.0.1",
        user_agent=request.headers.get("user-agent", "browser"),
        expires_at=session_expire
    )
    db.add(app_session)

    # Log Audit
    audit = AuditLog(
        user_id=user.id,
        event="LOGIN_SUCCESS",
        severity="info",
        ip_address=request.client.host if request.client else "127.0.0.1",
        action="LOGIN",
        metadata={"email": user.email}
    )
    db.add(audit)
    db.commit()

    response.set_cookie(key="access_token", value=token, httponly=True, samesite="lax", max_age=604800)

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user_to_response(user, db)
    )


@router.post("/logout")
def logout(response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Revoke sessions
    db.query(AppSession).filter(AppSession.user_id == user.id, AppSession.revoked == False).update({
        AppSession.revoked: True,
        AppSession.revoked_reason: "user_logout"
    })
    db.commit()
    response.delete_cookie(key="access_token")
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
def get_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return user_to_response(user, db)


@router.get("/session")
def check_session(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    profile = db.query(Profile).filter(Profile.id == user.id).first()
    roles = [r.role for r in db.query(UserRole).filter(UserRole.user_id == user.id).all()]
    return {
        "authenticated": True,
        "user_id": user.id,
        "email": user.email,
        "trust_score": profile.trust_score if profile else 100,
        "roles": roles
    }
