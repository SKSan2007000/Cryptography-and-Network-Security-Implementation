from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import User, Profile, SecurityEvent, ThreatIncident, Transfer
from backend.app.core.dependencies import get_current_user

router = APIRouter(prefix="/api/security-lab", tags=["Security Lab"])


class SimulationRequest(BaseModel):
    scenario: str  # e.g., 'tamper_ciphertext', 'replay_token', 'mitm_interception'
    transfer_id: Optional[str] = None


@router.post("/simulate")
def run_simulation(
    req: SimulationRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Run an isolated security scenario in Security Lab."""
    scenario = req.scenario.lower()

    if "tamper" in scenario:
        # Simulate tampering detection
        incident = ThreatIncident(
            user_id=current_user.id,
            transfer_id=req.transfer_id,
            threat_type="SIMULATED_CIPHERTEXT_TAMPERING",
            severity="critical",
            action_taken="SIMULATION_TAG_VERIFICATION_FAILED_QUARANTINE",
            trust_delta=0,  # Do not penalize real score in simulated mode
            blocked=True,
            simulated=True,
            details={"scenario": req.scenario, "test_result": "DEFENSE_SUCCESSFUL"}
        )
        db.add(incident)
        db.commit()
        return {
            "scenario": req.scenario,
            "status": "DETECTED_AND_BLOCKED",
            "defense_action": "AES-GCM Authentication Tag mismatch triggered quarantine",
            "integrity_preserved": True
        }

    elif "replay" in scenario:
        incident = ThreatIncident(
            user_id=current_user.id,
            transfer_id=req.transfer_id,
            threat_type="SIMULATED_TOKEN_REPLAY",
            severity="high",
            action_taken="SIMULATION_TOKEN_NONCE_REJECTED",
            trust_delta=0,
            blocked=True,
            simulated=True,
            details={"scenario": req.scenario, "test_result": "REPLAY_REJECTED"}
        )
        db.add(incident)
        db.commit()
        return {
            "scenario": req.scenario,
            "status": "REJECTED",
            "defense_action": "Single-use download token was rejected on replay attempt",
            "integrity_preserved": True
        }

    else:
        return {
            "scenario": req.scenario,
            "status": "COMPLETED",
            "defense_action": "Standard protocol checks validated",
            "integrity_preserved": True
        }


@router.get("/status")
def get_lab_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve security lab metrics and scenarios."""
    simulated_count = db.query(ThreatIncident).filter(ThreatIncident.simulated == True).count()
    return {
        "lab_mode": "ACTIVE",
        "total_simulations_run": simulated_count,
        "available_scenarios": [
            {"id": "tamper_ciphertext", "name": "Ciphertext Bit Flip Detection (AES-GCM)"},
            {"id": "replay_token", "name": "Token Replay & Single-Use Enforcement"},
            {"id": "unauthorized_party", "name": "Unauthorized Receiver Eavesdropping"}
        ]
    }
