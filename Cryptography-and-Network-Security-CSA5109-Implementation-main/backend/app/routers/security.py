from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, SecurityEvent, ThreatIncident, AuditLog, Profile
from backend.app.schemas.schemas import (
    SecurityEventCreate, ThreatIncidentCreate, ThreatIncidentResponse
)
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/security", tags=["Security & Threat Detection"])


@router.post("/events")
def record_security_event(
    req: SecurityEventCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ev = SecurityEvent(
        user_id=current_user.id,
        transfer_id=req.transfer_id,
        event_type=req.event_type,
        severity=req.severity,
        trust_delta=req.trust_delta,
        simulated=req.simulated,
        metadata_json=req.metadata
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return {"id": ev.id, "status": "recorded"}


@router.get("/events")
def list_security_events(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    events = db.query(SecurityEvent).filter(
        (SecurityEvent.user_id == current_user.id) | (SecurityEvent.user_id == None)
    ).order_by(SecurityEvent.created_at.desc()).limit(limit).all()
    return events


@router.post("/threats", response_model=ThreatIncidentResponse)
def record_threat_incident(
    req: ThreatIncidentCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    inc = ThreatIncident(
        user_id=req.user_id or current_user.id,
        transfer_id=req.transfer_id,
        threat_type=req.threat_type,
        severity=req.severity,
        action_taken=req.action_taken,
        trust_delta=req.trust_delta,
        blocked=req.blocked,
        simulated=req.simulated,
        details=req.details
    )
    db.add(inc)
    db.commit()
    db.refresh(inc)
    return inc


@router.get("/threats", response_model=List[ThreatIncidentResponse])
def list_threat_incidents(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    incidents = db.query(ThreatIncident).order_by(ThreatIncident.created_at.desc()).limit(limit).all()
    return incidents


@router.post("/threats/{incident_id}/resolve")
def resolve_threat_incident(
    incident_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    inc = db.query(ThreatIncident).filter(ThreatIncident.id == incident_id).first()
    if not inc:
        raise HTTPException(status_code=404, detail="Incident not found")
    inc.resolved = True
    db.commit()
    return {"message": "Incident marked as resolved"}
