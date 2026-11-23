"""Initial schema for SentinelCrypt PostgreSQL

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-11-23 23:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users
    op.create_table(
        'users',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 2. profiles
    op.create_table(
        'profiles',
        sa.Column('id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('organization', sa.String(255), nullable=True),
        sa.Column('trust_score', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('trust_status', sa.String(50), nullable=False, server_default="'TRUSTED'"),
        sa.Column('trust_updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('status', sa.String(50), nullable=False, server_default="'active'"),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 3. user_roles
    op.create_table(
        'user_roles',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('role', sa.String(50), nullable=False, server_default="'user'"),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 4. user_keys
    op.create_table(
        'user_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('public_key_jwk', sa.JSON(), nullable=False),
        sa.Column('wrapped_private_key', sa.Text(), nullable=False),
        sa.Column('kdf_salt', sa.String(255), nullable=False),
        sa.Column('wrap_iv', sa.String(255), nullable=False),
        sa.Column('algorithm', sa.String(100), nullable=False, server_default="'RSA-OAEP-2048-SHA256'"),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 5. devices
    op.create_table(
        'devices',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('fingerprint', sa.String(255), nullable=False),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('trusted', sa.Boolean(), nullable=False, server_default='false'),
    )

    # 6. app_sessions
    op.create_table(
        'app_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('device_fingerprint', sa.String(255), nullable=True),
        sa.Column('ip_address', sa.String(100), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_active', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('revoked_reason', sa.Text(), nullable=True),
    )

    # 7. transfers
    op.create_table(
        'transfers',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('sender_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('recipient_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('status', sa.String(50), nullable=False, server_default="'CREATED'"),
        sa.Column('security_level', sa.String(50), nullable=False, server_default="'standard'"),
        sa.Column('storage_path', sa.Text(), nullable=True),
        sa.Column('iv', sa.String(255), nullable=False),
        sa.Column('original_sha256', sa.String(64), nullable=False),
        sa.Column('ciphertext_sha256', sa.String(64), nullable=False),
        sa.Column('token_hash', sa.String(128), nullable=False),
        sa.Column('token_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('sender_token_wrapped', sa.Text(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('max_downloads', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('download_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('metrics', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('terminated_reason', sa.Text(), nullable=True),
        sa.Column('sender_latitude', sa.Numeric(9, 6), nullable=True),
        sa.Column('sender_longitude', sa.Numeric(9, 6), nullable=True),
        sa.Column('sender_location_accuracy', sa.Numeric(), nullable=True),
        sa.Column('sender_location_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('receiver_latitude', sa.Numeric(9, 6), nullable=True),
        sa.Column('receiver_longitude', sa.Numeric(9, 6), nullable=True),
        sa.Column('receiver_location_accuracy', sa.Numeric(), nullable=True),
        sa.Column('receiver_location_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 8. transfer_keys
    op.create_table(
        'transfer_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('wrapped_key', sa.Text(), nullable=False),
        sa.Column('wrap_algorithm', sa.String(100), nullable=False, server_default="'RSA-OAEP-SHA256'"),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 9. file_metadata
    op.create_table(
        'file_metadata',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='CASCADE'), unique=True, nullable=False),
        sa.Column('original_name', sa.Text(), nullable=False),
        sa.Column('mime_type', sa.String(255), nullable=False),
        sa.Column('size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('extension', sa.String(50), nullable=True),
        sa.Column('hash_algorithm', sa.String(50), nullable=False, server_default="'SHA-256'"),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 10. security_events
    op.create_table(
        'security_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('event_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False, server_default="'info'"),
        sa.Column('ip_address', sa.String(100), nullable=True),
        sa.Column('trust_delta', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('simulated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('metadata', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 11. threat_incidents
    op.create_table(
        'threat_incidents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('threat_type', sa.String(100), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False),
        sa.Column('action_taken', sa.Text(), nullable=False),
        sa.Column('trust_delta', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('blocked', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('simulated', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('details', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('resolved', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 12. trust_events
    op.create_table(
        'trust_events',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('security_event_id', sa.String(36), sa.ForeignKey('security_events.id', ondelete='SET NULL'), nullable=True),
        sa.Column('previous_score', sa.Integer(), nullable=False),
        sa.Column('delta', sa.Integer(), nullable=False),
        sa.Column('new_score', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 13. notifications
    op.create_table(
        'notifications',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='CASCADE'), nullable=True),
        sa.Column('title', sa.Text(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False, server_default="'info'"),
        sa.Column('read', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )

    # 14. audit_logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True, index=True),
        sa.Column('transfer_id', sa.String(36), sa.ForeignKey('transfers.id', ondelete='SET NULL'), nullable=True),
        sa.Column('event', sa.Text(), nullable=False),
        sa.Column('severity', sa.String(50), nullable=False, server_default="'info'"),
        sa.Column('ip_address', sa.String(100), nullable=True),
        sa.Column('action', sa.Text(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('notifications')
    op.drop_table('trust_events')
    op.drop_table('threat_incidents')
    op.drop_table('security_events')
    op.drop_table('file_metadata')
    op.drop_table('transfer_keys')
    op.drop_table('transfers')
    op.drop_table('app_sessions')
    op.drop_table('devices')
    op.drop_table('user_keys')
    op.drop_table('user_roles')
    op.drop_table('profiles')
    op.drop_table('users')
