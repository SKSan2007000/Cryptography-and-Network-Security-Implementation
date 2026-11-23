from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, TrustEvent
from backend.app.schemas.schemas import TrustEventResponse
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/trust", tags=["Trust Score Engine"])


class TrustAdjustRequest(BaseModel):
    user_id: str
    delta: int
    reason: str


@router.get("/events", response_model=List[TrustEventResponse])
def get_trust_events(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get history of trust score changes for the current user."""
    events = db.query(TrustEvent).filter(
        TrustEvent.user_id == current_user.id
    ).order_by(TrustEvent.created_at.desc()).all()
    return events


@router.post("/adjust")
def adjust_trust_score(
    req: TrustAdjustRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Adjust a user's trust score and record the trust event."""
    profile = db.query(Profile).filter(Profile.id == req.user_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    prev = profile.trust_score
    new_score = max(0, min(100, prev + req.delta))
    profile.trust_score = new_score

    if new_score >= 85:
        profile.trust_status = "TRUSTED"
    elif new_score >= 65:
        profile.trust_status = "NORMAL"
    elif new_score >= 40:
        profile.trust_status = "CAUTION"
    else:
        profile.trust_status = "HIGH RISK"

    ev = TrustEvent(
        user_id=profile.id,
        previous_score=prev,
        delta=req.delta,
        new_score=new_score,
        reason=req.reason
    )
    db.add(ev)
    db.commit()

    return {
        "user_id": profile.id,
        "previous_score": prev,
        "new_score": new_score,
        "trust_status": profile.trust_status
    }
