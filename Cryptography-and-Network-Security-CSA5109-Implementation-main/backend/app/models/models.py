import uuid
from sqlalchemy import (
    Column, String, Integer, BigInteger, Boolean, DateTime,
    ForeignKey, Text, Numeric, func
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.types import JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    profile = relationship("Profile", back_populates="user", uselist=False, cascade="all, delete-orphan")
    roles = relationship("UserRole", back_populates="user", cascade="all, delete-orphan")
    user_keys = relationship("UserKey", back_populates="user", uselist=False, cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    sessions = relationship("AppSession", back_populates="user", cascade="all, delete-orphan")


class Profile(Base):
    __tablename__ = "profiles"

    id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    email = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    organization = Column(String(255), nullable=True)
    trust_score = Column(Integer, default=100, nullable=False)
    trust_status = Column(String(50), default="TRUSTED", nullable=False)
    trust_updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    status = Column(String(50), default="active", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    user = relationship("User", back_populates="profile")


class UserRole(Base):
    __tablename__ = "user_roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(50), default="user", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="roles")


class UserKey(Base):
    __tablename__ = "user_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    public_key_jwk = Column(JSON, nullable=False)
    wrapped_private_key = Column(Text, nullable=False)
    kdf_salt = Column(String(255), nullable=False)
    wrap_iv = Column(String(255), nullable=False)
    algorithm = Column(String(100), default="RSA-OAEP-2048-SHA256", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="user_keys")


class Device(Base):
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint = Column(String(255), nullable=False)
    user_agent = Column(Text, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_seen = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    trusted = Column(Boolean, default=False, nullable=False)

    user = relationship("User", back_populates="devices")


class AppSession(Base):
    __tablename__ = "app_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    device_fingerprint = Column(String(255), nullable=True)
    ip_address = Column(String(100), nullable=True)
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_active = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    revoked_reason = Column(Text, nullable=True)

    user = relationship("User", back_populates="sessions")


class Transfer(Base):
    __tablename__ = "transfers"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    sender_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    recipient_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(50), default="CREATED", nullable=False)
    security_level = Column(String(50), default="standard", nullable=False)
    storage_path = Column(Text, nullable=True)
    iv = Column(String(255), nullable=False)
    original_sha256 = Column(String(64), nullable=False)
    ciphertext_sha256 = Column(String(64), nullable=False)
    token_hash = Column(String(128), nullable=False)
    token_used_at = Column(DateTime(timezone=True), nullable=True)
    sender_token_wrapped = Column(Text, nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    max_downloads = Column(Integer, default=1, nullable=False)
    download_count = Column(Integer, default=0, nullable=False)
    failed_attempts = Column(Integer, default=0, nullable=False)
    metrics = Column(JSON, default=dict, nullable=False)
    terminated_reason = Column(Text, nullable=True)
    sender_latitude = Column(Numeric(9, 6), nullable=True)
    sender_longitude = Column(Numeric(9, 6), nullable=True)
    sender_location_accuracy = Column(Numeric, nullable=True)
    sender_location_timestamp = Column(DateTime(timezone=True), nullable=True)
    receiver_latitude = Column(Numeric(9, 6), nullable=True)
    receiver_longitude = Column(Numeric(9, 6), nullable=True)
    receiver_location_accuracy = Column(Numeric, nullable=True)
    receiver_location_timestamp = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    transfer_key = relationship("TransferKey", back_populates="transfer", uselist=False, cascade="all, delete-orphan")
    file_metadata = relationship("FileMetadata", back_populates="transfer", uselist=False, cascade="all, delete-orphan")


class TransferKey(Base):
    __tablename__ = "transfer_keys"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="CASCADE"), unique=True, nullable=False)
    wrapped_key = Column(Text, nullable=False)
    wrap_algorithm = Column(String(100), default="RSA-OAEP-SHA256", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    transfer = relationship("Transfer", back_populates="transfer_key")


class FileMetadata(Base):
    __tablename__ = "file_metadata"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="CASCADE"), unique=True, nullable=False)
    original_name = Column(Text, nullable=False)
    mime_type = Column(String(255), nullable=False)
    size_bytes = Column(BigInteger, nullable=False)
    extension = Column(String(50), nullable=True)
    hash_algorithm = Column(String(50), default="SHA-256", nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    transfer = relationship("Transfer", back_populates="file_metadata")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(50), default="info", nullable=False)
    ip_address = Column(String(100), nullable=True)
    trust_delta = Column(Integer, default=0, nullable=False)
    simulated = Column(Boolean, default=False, nullable=False)
    metadata_json = Column("metadata", JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ThreatIncident(Base):
    __tablename__ = "threat_incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="SET NULL"), nullable=True, index=True)
    threat_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    action_taken = Column(Text, nullable=False)
    trust_delta = Column(Integer, default=0, nullable=False)
    blocked = Column(Boolean, default=True, nullable=False)
    simulated = Column(Boolean, default=False, nullable=False)
    details = Column(JSON, default=dict, nullable=False)
    resolved = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class TrustEvent(Base):
    __tablename__ = "trust_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    security_event_id = Column(String(36), ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True)
    previous_score = Column(Integer, nullable=False)
    delta = Column(Integer, nullable=False)
    new_score = Column(Integer, nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="CASCADE"), nullable=True)
    title = Column(Text, nullable=False)
    body = Column(Text, nullable=False)
    severity = Column(String(50), default="info", nullable=False)
    read = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    transfer_id = Column(String(36), ForeignKey("transfers.id", ondelete="SET NULL"), nullable=True)
    event = Column(Text, nullable=False)
    severity = Column(String(50), default="info", nullable=False)
    ip_address = Column(String(100), nullable=True)
    action = Column(Text, nullable=True)
    metadata_json = Column("metadata", JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
