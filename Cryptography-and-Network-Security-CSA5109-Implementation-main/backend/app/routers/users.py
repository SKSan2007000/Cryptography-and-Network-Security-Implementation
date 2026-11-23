from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, UserKey, AuditLog
from backend.app.schemas.schemas import (
    ProfileResponse, ProfileUpdateRequest, RegisterKeyRequest,
    UserKeyResponse, PublicKeyResponse
)
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/users", tags=["Users & Key Management"])


@router.get("", response_model=List[ProfileResponse])
def list_recipients(
    query: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List eligible recipients for file transfer (excluding current user)."""
    q = db.query(Profile).join(User, Profile.id == User.id).filter(
        User.is_active == True,
        User.id != current_user.id
    )
    if query:
        pattern = f"%{query.lower()}%"
        q = q.filter(
            (Profile.email.ilike(pattern)) |
            (Profile.full_name.ilike(pattern)) |
            (Profile.organization.ilike(pattern))
        )
    profiles = q.all()
    return profiles


@router.get("/{user_id}/public-key", response_model=PublicKeyResponse)
def get_user_public_key(user_id: str, db: Session = Depends(get_db)):
    """Retrieve public RSA-OAEP JWK for recipient key wrapping."""
    key_rec = db.query(UserKey).filter(UserKey.user_id == user_id).first()
    if not key_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient has not published an RSA public key yet"
        )
    return PublicKeyResponse(
        user_id=key_rec.user_id,
        public_key_jwk=key_rec.public_key_jwk
    )


@router.post("/keys", response_model=UserKeyResponse)
def register_user_keys(
    req: RegisterKeyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register or update user's RSA-OAEP public key and passphrase-wrapped private key."""
    key_rec = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if key_rec:
        key_rec.public_key_jwk = req.public_key_jwk
        key_rec.wrapped_private_key = req.wrapped_private_key
        key_rec.kdf_salt = req.kdf_salt
        key_rec.wrap_iv = req.wrap_iv
        key_rec.algorithm = req.algorithm
    else:
        key_rec = UserKey(
            user_id=current_user.id,
            public_key_jwk=req.public_key_jwk,
            wrapped_private_key=req.wrapped_private_key,
            kdf_salt=req.kdf_salt,
            wrap_iv=req.wrap_iv,
            algorithm=req.algorithm
        )
        db.add(key_rec)

    audit = AuditLog(
        user_id=current_user.id,
        event="KEYPAIR_REGISTERED",
        severity="info",
        action="KEY_REGISTER",
        metadata={"algorithm": req.algorithm}
    )
    db.add(audit)
    db.commit()
    db.refresh(key_rec)

    return key_rec


@router.get("/keys/me", response_model=UserKeyResponse)
def get_my_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve current user's key pair (contains passphrase-wrapped private key)."""
    key_rec = db.query(UserKey).filter(UserKey.user_id == current_user.id).first()
    if not key_rec:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No cryptographic keys found for this account"
        )
    return key_rec


@router.put("/profile", response_model=ProfileResponse)
def update_profile(
    req: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update profile details."""
    profile = db.query(Profile).filter(Profile.id == current_user.id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    if req.full_name is not None:
        profile.full_name = req.full_name
    if req.organization is not None:
        profile.organization = req.organization
    db.commit()
    db.refresh(profile)
    return profile
