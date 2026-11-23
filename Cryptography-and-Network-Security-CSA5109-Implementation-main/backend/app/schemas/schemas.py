from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# ---------------- Auth Schemas ----------------
class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: Optional[str] = None
    organization: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProfileResponse(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    organization: Optional[str] = None
    trust_score: int = 100
    trust_status: str = "TRUSTED"
    status: str = "active"
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProfileUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    organization: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    is_active: bool
    profile: Optional[ProfileResponse] = None
    roles: List[str] = []
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ---------------- Key Schemas ----------------
class RegisterKeyRequest(BaseModel):
    public_key_jwk: Dict[str, Any]
    wrapped_private_key: str
    kdf_salt: str
    wrap_iv: str
    algorithm: str = "RSA-OAEP-2048-SHA256"


class UserKeyResponse(BaseModel):
    id: str
    user_id: str
    public_key_jwk: Dict[str, Any]
    wrapped_private_key: str
    kdf_salt: str
    wrap_iv: str
    algorithm: str

    model_config = ConfigDict(from_attributes=True)


class PublicKeyResponse(BaseModel):
    user_id: str
    public_key_jwk: Dict[str, Any]


# ---------------- Transfer Schemas ----------------
class CreateTransferRequest(BaseModel):
    recipient_id: str
    security_level: str = "standard"
    iv: str
    original_sha256: str
    ciphertext_sha256: str
    token_hash: str
    expires_at: datetime
    max_downloads: int = 1
    wrapped_key: str
    wrap_algorithm: str = "RSA-OAEP-SHA256"
    file_name: str
    file_size: int
    mime_type: str = "application/octet-stream"
    extension: Optional[str] = None
    sender_token_wrapped: Optional[str] = None
    sender_latitude: Optional[float] = None
    sender_longitude: Optional[float] = None
    sender_location_accuracy: Optional[float] = None


class FileMetadataResponse(BaseModel):
    id: str
    original_name: str
    mime_type: str
    size_bytes: int
    extension: Optional[str] = None
    hash_algorithm: str = "SHA-256"

    model_config = ConfigDict(from_attributes=True)


class TransferKeyResponse(BaseModel):
    wrapped_key: str
    wrap_algorithm: str

    model_config = ConfigDict(from_attributes=True)


class TransferResponse(BaseModel):
    id: str
    sender_id: str
    recipient_id: str
    status: str
    security_level: str
    storage_path: Optional[str] = None
    iv: str
    original_sha256: str
    ciphertext_sha256: str
    expires_at: datetime
    max_downloads: int
    download_count: int
    failed_attempts: int
    terminated_reason: Optional[str] = None
    sender_latitude: Optional[float] = None
    sender_longitude: Optional[float] = None
    receiver_latitude: Optional[float] = None
    receiver_longitude: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    file_metadata: Optional[FileMetadataResponse] = None
    transfer_key: Optional[TransferKeyResponse] = None
    sender_email: Optional[str] = None
    recipient_email: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class TransferFailRequest(BaseModel):
    reason: str
    is_tampered: bool = False


# ---------------- Security & Trust Schemas ----------------
class SecurityEventCreate(BaseModel):
    event_type: str
    severity: str = "info"
    transfer_id: Optional[str] = None
    trust_delta: int = 0
    simulated: bool = False
    metadata: Dict[str, Any] = {}


class ThreatIncidentCreate(BaseModel):
    threat_type: str
    severity: str = "high"
    action_taken: str = "quarantine"
    transfer_id: Optional[str] = None
    user_id: Optional[str] = None
    trust_delta: int = -20
    blocked: bool = True
    simulated: bool = False
    details: Dict[str, Any] = {}


class ThreatIncidentResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    transfer_id: Optional[str] = None
    threat_type: str
    severity: str
    action_taken: str
    trust_delta: int
    blocked: bool
    simulated: bool
    details: Dict[str, Any] = {}
    resolved: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TrustEventResponse(BaseModel):
    id: str
    user_id: str
    security_event_id: Optional[str] = None
    previous_score: int
    delta: int
    new_score: int
    reason: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------- Location & Digital Twin ----------------
class LocationConsentRequest(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracy: Optional[float] = None


class DigitalTwinNode(BaseModel):
    id: str
    label: str
    type: str  # sender, receiver, threat, incident
    latitude: float
    longitude: float
    trust_score: int = 100
    status: str = "active"


# ---------------- Notification & Audit ----------------
class NotificationResponse(BaseModel):
    id: str
    user_id: str
    transfer_id: Optional[str] = None
    title: str
    body: str
    severity: str
    read: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    transfer_id: Optional[str] = None
    event: str
    severity: str
    ip_address: Optional[str] = None
    action: Optional[str] = None
    metadata: Dict[str, Any] = {}
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
