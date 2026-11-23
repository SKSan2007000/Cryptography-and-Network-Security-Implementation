from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, Transfer, ThreatIncident
from backend.app.schemas.schemas import LocationConsentRequest, DigitalTwinNode
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/digital-twin", tags=["Digital Twin & Geolocation"])


@router.post("/location")
def update_user_location(
    req: LocationConsentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update consented geolocation coordinates for the current user."""
    # Store in latest active transfer or session
    transfer = db.query(Transfer).filter(
        Transfer.sender_id == current_user.id
    ).order_by(Transfer.created_at.desc()).first()
    if transfer:
        transfer.sender_latitude = req.latitude
        transfer.sender_longitude = req.longitude
        transfer.sender_location_accuracy = req.accuracy
        db.commit()

    return {
        "status": "consented_location_updated",
        "latitude": req.latitude,
        "longitude": req.longitude
    }


@router.get("/nodes", response_model=List[DigitalTwinNode])
def get_digital_twin_nodes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve geospatial nodes for Digital Twin map visualization."""
    nodes = []

    # Transfers with locations
    transfers = db.query(Transfer).filter(
        (Transfer.sender_latitude != None) & (Transfer.sender_longitude != None)
    ).limit(30).all()

    for t in transfers:
        sender_prof = db.query(Profile).filter(Profile.id == t.sender_id).first()
        nodes.append(DigitalTwinNode(
            id=f"sender-{t.id}",
            label=f"Sender: {sender_prof.email if sender_prof else 'Node'}",
            type="sender",
            latitude=float(t.sender_latitude),
            longitude=float(t.sender_longitude),
            trust_score=sender_prof.trust_score if sender_prof else 100,
            status=t.status
        ))

        if t.receiver_latitude and t.receiver_longitude:
            rec_prof = db.query(Profile).filter(Profile.id == t.recipient_id).first()
            nodes.append(DigitalTwinNode(
                id=f"receiver-{t.id}",
                label=f"Receiver: {rec_prof.email if rec_prof else 'Node'}",
                type="receiver",
                latitude=float(t.receiver_latitude),
                longitude=float(t.receiver_longitude),
                trust_score=rec_prof.trust_score if rec_prof else 100,
                status=t.status
            ))

    return nodes


@router.get("/telemetry")
def get_twin_telemetry(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve aggregate telemetry for Digital Twin dashboard."""
    active_transfers = db.query(Transfer).filter(Transfer.status.in_(["CREATED", "ENCRYPTED", "TRANSFERRING"])).count()
    completed_transfers = db.query(Transfer).filter(Transfer.status == "COMPLETED").count()
    threats_count = db.query(ThreatIncident).count()
    total_users = db.query(User).count()

    return {
        "active_transfers": active_transfers,
        "completed_transfers": completed_transfers,
        "threats_detected": threats_count,
        "total_nodes": total_users,
        "system_health": "OPTIMAL",
        "encryption_standard": "AES-256-GCM / RSA-OAEP-2048"
    }
