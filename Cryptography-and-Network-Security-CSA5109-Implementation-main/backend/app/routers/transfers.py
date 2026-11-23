import hashlib
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Response
from fastapi.responses import StreamingResponse
import io
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models.models import (
    User, Profile, Transfer, TransferKey, FileMetadata,
    Notification, SecurityEvent, ThreatIncident, TrustEvent, AuditLog
)
from backend.app.schemas.schemas import (
    CreateTransferRequest, TransferResponse, FileMetadataResponse,
    TransferKeyResponse, TransferFailRequest
)
from backend.app.core.dependencies import get_current_user
from backend.app.core.storage import (
    save_encrypted_payload, read_encrypted_payload, delete_encrypted_payload
)

router = APIRouter(prefix="/api/transfers", tags=["Transfers"])


def build_transfer_response(t: Transfer, db: Session) -> TransferResponse:
    sender_prof = db.query(Profile).filter(Profile.id == t.sender_id).first()
    recipient_prof = db.query(Profile).filter(Profile.id == t.recipient_id).first()
    fm_resp = FileMetadataResponse.model_validate(t.file_metadata) if t.file_metadata else None
    tk_resp = TransferKeyResponse(
        wrapped_key=t.transfer_key.wrapped_key,
        wrap_algorithm=t.transfer_key.wrap_algorithm
    ) if t.transfer_key else None

    return TransferResponse(
        id=t.id,
        sender_id=t.sender_id,
        recipient_id=t.recipient_id,
        status=t.status,
        security_level=t.security_level,
        storage_path=t.storage_path,
        iv=t.iv,
        original_sha256=t.original_sha256,
        ciphertext_sha256=t.ciphertext_sha256,
        expires_at=t.expires_at,
        max_downloads=t.max_downloads,
        download_count=t.download_count,
        failed_attempts=t.failed_attempts,
        terminated_reason=t.terminated_reason,
        sender_latitude=float(t.sender_latitude) if t.sender_latitude is not None else None,
        sender_longitude=float(t.sender_longitude) if t.sender_longitude is not None else None,
        receiver_latitude=float(t.receiver_latitude) if t.receiver_latitude is not None else None,
        receiver_longitude=float(t.receiver_longitude) if t.receiver_longitude is not None else None,
        created_at=t.created_at,
        updated_at=t.updated_at,
        file_metadata=fm_resp,
        transfer_key=tk_resp,
        sender_email=sender_prof.email if sender_prof else None,
        recipient_email=recipient_prof.email if recipient_prof else None
    )


@router.post("", response_model=TransferResponse)
def create_transfer(
    req: CreateTransferRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Initiate a secure transfer record with wrapped key and file metadata."""
    # Validate recipient
    recipient = db.query(User).filter(User.id == req.recipient_id, User.is_active == True).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient not found or account inactive")
    if recipient.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot send transfer to yourself")

    transfer = Transfer(
        sender_id=current_user.id,
        recipient_id=recipient.id,
        status="CREATED",
        security_level=req.security_level,
        iv=req.iv,
        original_sha256=req.original_sha256,
        ciphertext_sha256=req.ciphertext_sha256,
        token_hash=req.token_hash,
        sender_token_wrapped=req.sender_token_wrapped,
        expires_at=req.expires_at,
        max_downloads=req.max_downloads,
        sender_latitude=req.sender_latitude,
        sender_longitude=req.sender_longitude,
        sender_location_accuracy=req.sender_location_accuracy,
        sender_location_timestamp=datetime.now(timezone.utc) if req.sender_latitude else None
    )
    db.add(transfer)
    db.flush()

    # Add transfer key
    tk = TransferKey(
        transfer_id=transfer.id,
        wrapped_key=req.wrapped_key,
        wrap_algorithm=req.wrap_algorithm
    )
    db.add(tk)

    # Add file metadata
    fm = FileMetadata(
        transfer_id=transfer.id,
        original_name=req.file_name,
        mime_type=req.mime_type,
        size_bytes=req.file_size,
        extension=req.extension or (req.file_name.split(".")[-1] if "." in req.file_name else None),
        hash_algorithm="SHA-256"
    )
    db.add(fm)

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        transfer_id=transfer.id,
        event="TRANSFER_CREATED",
        severity="info",
        action="CREATE_TRANSFER",
        metadata={"recipient_id": recipient.id, "file_name": req.file_name, "size": req.file_size}
    )
    db.add(audit)
    db.commit()
    db.refresh(transfer)

    return build_transfer_response(transfer, db)


@router.post("/{transfer_id}/upload")
async def upload_encrypted_payload(
    transfer_id: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Upload encrypted ciphertext payload to storage."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if transfer.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only sender can upload payload")

    data = await file.read()
    # Compute ciphertext hash
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash.lower() != transfer.ciphertext_sha256.lower():
        raise HTTPException(
            status_code=400,
            detail=f"Uploaded payload checksum mismatch (expected {transfer.ciphertext_sha256}, got {actual_hash})"
        )

    # Save to disk
    rel_path = f"{transfer.id}.bin"
    saved_path = save_encrypted_payload(rel_path, data)

    transfer.storage_path = saved_path
    transfer.status = "ENCRYPTED"

    # Notify recipient
    notif = Notification(
        user_id=transfer.recipient_id,
        transfer_id=transfer.id,
        title="New Secure Transfer Received",
        body=f"You have received an encrypted transfer from {current_user.email}",
        severity="info"
    )
    db.add(notif)
    db.commit()

    return {"message": "Encrypted payload uploaded successfully", "storage_path": saved_path}


@router.get("", response_model=List[TransferResponse])
def list_transfers(
    filter: Optional[str] = None,  # 'inbox', 'sent', or None
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List transfers addressed to or sent by the current user."""
    q = db.query(Transfer)
    if filter == "inbox":
        q = q.filter(Transfer.recipient_id == current_user.id)
    elif filter == "sent":
        q = q.filter(Transfer.sender_id == current_user.id)
    else:
        q = q.filter((Transfer.recipient_id == current_user.id) | (Transfer.sender_id == current_user.id))

    transfers = q.order_by(Transfer.created_at.desc()).all()
    return [build_transfer_response(t, db) for t in transfers]


@router.get("/{transfer_id}", response_model=TransferResponse)
def get_transfer_detail(
    transfer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve transfer details. Rejects unauthorized access and records threat event."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    # Access authorization
    if transfer.sender_id != current_user.id and transfer.recipient_id != current_user.id:
        # Dynamic threat detection: record unauthorized access
        profile = db.query(Profile).filter(Profile.id == current_user.id).first()
        prev_score = profile.trust_score if profile else 100
        new_score = max(0, prev_score - 30)
        if profile:
            profile.trust_score = new_score
            profile.trust_status = "HIGH RISK" if new_score < 40 else "CAUTION"

        incident = ThreatIncident(
            user_id=current_user.id,
            transfer_id=transfer.id,
            threat_type="UNAUTHORIZED_TRANSFER_ACCESS",
            severity="high",
            action_taken="ACCESS_BLOCKED_TRUST_PENALTY",
            trust_delta=-30,
            blocked=True,
            details={"attempted_by": current_user.email, "transfer_id": transfer.id}
        )
        db.add(incident)

        trust_event = TrustEvent(
            user_id=current_user.id,
            previous_score=prev_score,
            delta=-30,
            new_score=new_score,
            reason=f"Attempted unauthorized inspection of transfer {transfer.id}"
        )
        db.add(trust_event)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized: You are neither the sender nor the designated recipient of this transfer"
        )

    return build_transfer_response(transfer, db)


@router.get("/{transfer_id}/download")
def download_encrypted_payload(
    transfer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Download encrypted file payload. Enforces recipient checks, limits, and expiration."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    # 1. Recipient authorization
    if transfer.recipient_id != current_user.id:
        # Threat incident
        profile = db.query(Profile).filter(Profile.id == current_user.id).first()
        prev_score = profile.trust_score if profile else 100
        new_score = max(0, prev_score - 30)
        if profile:
            profile.trust_score = new_score
            profile.trust_status = "HIGH RISK" if new_score < 40 else "CAUTION"

        # Quarantine transfer
        transfer.status = "PAUSED"
        transfer.terminated_reason = f"Quarantined due to unauthorized download attempt by {current_user.email}"

        incident = ThreatIncident(
            user_id=current_user.id,
            transfer_id=transfer.id,
            threat_type="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
            severity="critical",
            action_taken="TRANSFER_QUARANTINED_ACCESS_BLOCKED",
            trust_delta=-30,
            blocked=True,
            details={"attacker_id": current_user.id, "attacker_email": current_user.email}
        )
        db.add(incident)

        trust_event = TrustEvent(
            user_id=current_user.id,
            previous_score=prev_score,
            delta=-30,
            new_score=new_score,
            reason=f"Attempted unauthorized download of transfer {transfer.id}"
        )
        db.add(trust_event)
        db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Unauthorized recipient. Transfer quarantined and security incident reported."
        )

    # 2. Status verification
    if transfer.status in ["TERMINATED", "REVOKED", "PAUSED"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Transfer cannot be downloaded (status: {transfer.status}). {transfer.terminated_reason or ''}"
        )

    # 3. Expiration verification
    now = datetime.now(timezone.utc)
    if transfer.expires_at < now:
        transfer.status = "EXPIRED"
        db.commit()
        raise HTTPException(status_code=410, detail="Transfer has expired")

    # 4. Download limits
    if transfer.download_count >= transfer.max_downloads:
        transfer.status = "EXHAUSTED"
        db.commit()
        raise HTTPException(status_code=400, detail="Maximum download limit reached for this transfer")

    if not transfer.storage_path:
        raise HTTPException(status_code=404, detail="Ciphertext payload has not been uploaded yet")

    payload_bytes = read_encrypted_payload(transfer.storage_path)

    # Increment download count
    transfer.download_count += 1
    transfer.status = "TRANSFERRING"

    # Audit log
    audit = AuditLog(
        user_id=current_user.id,
        transfer_id=transfer.id,
        event="PAYLOAD_DOWNLOADED",
        severity="info",
        action="DOWNLOAD",
        metadata={"download_count": transfer.download_count}
    )
    db.add(audit)
    db.commit()

    return StreamingResponse(
        io.BytesIO(payload_bytes),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{transfer_id}.bin"',
            "X-Ciphertext-SHA256": transfer.ciphertext_sha256,
            "X-IV": transfer.iv
        }
    )


@router.post("/{transfer_id}/complete")
def complete_transfer(
    transfer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Mark transfer as COMPLETED upon receiver SHA-256 verification."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if transfer.recipient_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only recipient can complete verification")

    transfer.status = "COMPLETED"

    # Notify sender
    notif = Notification(
        user_id=transfer.sender_id,
        transfer_id=transfer.id,
        title="Transfer Successfully Received",
        body=f"Recipient {current_user.email} successfully decrypted and verified the transfer.",
        severity="info"
    )
    db.add(notif)

    audit = AuditLog(
        user_id=current_user.id,
        transfer_id=transfer.id,
        event="TRANSFER_COMPLETED_VERIFIED",
        severity="info",
        action="COMPLETE",
        metadata={"original_sha256": transfer.original_sha256}
    )
    db.add(audit)
    db.commit()

    return {"message": "Transfer successfully completed and verified"}


@router.post("/{transfer_id}/fail")
def fail_transfer(
    transfer_id: str,
    req: TransferFailRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Record verification failure, tag tampering, or integrity violation."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")

    transfer.failed_attempts += 1
    if req.is_tampered or transfer.failed_attempts >= 3:
        transfer.status = "TERMINATED"
        transfer.terminated_reason = f"Integrity failure: {req.reason}"

        incident = ThreatIncident(
            user_id=current_user.id,
            transfer_id=transfer.id,
            threat_type="INTEGRITY_TAMPERING_DETECTED",
            severity="critical",
            action_taken="TRANSFER_TERMINATED_SECURITY_ALERT",
            trust_delta=-40,
            blocked=True,
            details={"reason": req.reason, "attempts": transfer.failed_attempts}
        )
        db.add(incident)

    audit = AuditLog(
        user_id=current_user.id,
        transfer_id=transfer.id,
        event="TRANSFER_VERIFICATION_FAILED",
        severity="critical" if req.is_tampered else "warning",
        action="FAIL",
        metadata={"reason": req.reason, "attempts": transfer.failed_attempts}
    )
    db.add(audit)
    db.commit()

    return {"message": "Failure recorded", "status": transfer.status}


@router.post("/{transfer_id}/revoke")
def revoke_transfer(
    transfer_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke an active transfer."""
    transfer = db.query(Transfer).filter(Transfer.id == transfer_id).first()
    if not transfer:
        raise HTTPException(status_code=404, detail="Transfer not found")
    if transfer.sender_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only sender can revoke this transfer")

    transfer.status = "REVOKED"
    transfer.terminated_reason = "Revoked by sender"

    audit = AuditLog(
        user_id=current_user.id,
        transfer_id=transfer.id,
        event="TRANSFER_REVOKED",
        severity="info",
        action="REVOKE",
        metadata={}
    )
    db.add(audit)
    db.commit()

    return {"message": "Transfer successfully revoked"}
