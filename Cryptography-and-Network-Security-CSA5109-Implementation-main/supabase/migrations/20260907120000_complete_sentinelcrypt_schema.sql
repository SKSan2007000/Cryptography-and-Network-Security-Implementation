-- Migration: Complete SentinelCrypt Database Schema
-- Includes profiles, user_roles, user_keys, devices, app_sessions, transfers, transfer_keys,
-- file_metadata, security_events, threat_incidents, audit_logs, notifications, trust_events,
-- storage buckets, RLS policies, helper functions, and triggers.

-- 1. EXTENSIONS
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 2. ENUMS & ROLES
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'app_role') THEN
    CREATE TYPE public.app_role AS ENUM ('admin', 'user');
  END IF;
END $$;

-- 3. PROFILES TABLE (Trust Score, Trust Status, Account Status)
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  full_name TEXT,
  organization TEXT,
  trust_score INT NOT NULL DEFAULT 100 CHECK (trust_score >= 0 AND trust_score <= 100),
  trust_status TEXT NOT NULL DEFAULT 'TRUSTED' CHECK (trust_status IN ('TRUSTED', 'NORMAL', 'CAUTION', 'HIGH RISK')),
  trust_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 4. USER ROLES (RBAC)
CREATE TABLE IF NOT EXISTS public.user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role public.app_role NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);

-- 5. USER CRYPTOGRAPHIC KEYS (Public RSA Key & Wrapped Private Key)
CREATE TABLE IF NOT EXISTS public.user_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE UNIQUE,
  public_key_jwk JSONB NOT NULL,
  wrapped_private_key TEXT NOT NULL,
  kdf_salt TEXT NOT NULL,
  wrap_iv TEXT NOT NULL,
  algorithm TEXT NOT NULL DEFAULT 'RSA-OAEP-2048-SHA256',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 6. TRUSTED DEVICES & FINGERPRINTS
CREATE TABLE IF NOT EXISTS public.devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  user_agent TEXT,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  trusted BOOLEAN NOT NULL DEFAULT false,
  UNIQUE (user_id, fingerprint)
);

-- 7. APPLICATION SESSIONS (Session Integrity & Anomaly Tracking)
CREATE TABLE IF NOT EXISTS public.app_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  device_fingerprint TEXT,
  ip_address TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_active TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '12 hours'),
  revoked BOOLEAN NOT NULL DEFAULT false,
  revoked_reason TEXT
);

-- 8. TRANSFERS (Secure Transfer Lifecycle & Geolocation Telemetry)
CREATE TABLE IF NOT EXISTS public.transfers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  recipient_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'CREATED',
  security_level TEXT NOT NULL DEFAULT 'standard',
  storage_path TEXT,
  iv TEXT NOT NULL,
  original_sha256 TEXT NOT NULL,
  ciphertext_sha256 TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_used_at TIMESTAMPTZ,
  sender_token_wrapped TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  max_downloads INT NOT NULL DEFAULT 1,
  download_count INT NOT NULL DEFAULT 0,
  failed_attempts INT NOT NULL DEFAULT 0,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  terminated_reason TEXT,
  sender_latitude NUMERIC(9,6),
  sender_longitude NUMERIC(9,6),
  sender_location_accuracy NUMERIC,
  sender_location_timestamp TIMESTAMPTZ,
  receiver_latitude NUMERIC(9,6),
  receiver_longitude NUMERIC(9,6),
  receiver_location_accuracy NUMERIC,
  receiver_location_timestamp TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT chk_sender_lat CHECK (sender_latitude IS NULL OR (sender_latitude >= -90 AND sender_latitude <= 90)),
  CONSTRAINT chk_sender_lng CHECK (sender_longitude IS NULL OR (sender_longitude >= -180 AND sender_longitude <= 180)),
  CONSTRAINT chk_receiver_lat CHECK (receiver_latitude IS NULL OR (receiver_latitude >= -90 AND receiver_latitude <= 90)),
  CONSTRAINT chk_receiver_lng CHECK (receiver_longitude IS NULL OR (receiver_longitude >= -180 AND receiver_longitude <= 180))
);

-- 9. TRANSFER KEYS (Wrapped AES Keys per Transfer)
CREATE TABLE IF NOT EXISTS public.transfer_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transfer_id UUID NOT NULL REFERENCES public.transfers(id) ON DELETE CASCADE UNIQUE,
  wrapped_key TEXT NOT NULL,
  wrap_algorithm TEXT NOT NULL DEFAULT 'RSA-OAEP-SHA256',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 10. FILE METADATA
CREATE TABLE IF NOT EXISTS public.file_metadata (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  transfer_id UUID NOT NULL REFERENCES public.transfers(id) ON DELETE CASCADE UNIQUE,
  original_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  extension TEXT,
  hash_algorithm TEXT NOT NULL DEFAULT 'SHA-256',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 11. SECURITY EVENTS (Detection & Telemetry)
CREATE TABLE IF NOT EXISTS public.security_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  transfer_id UUID REFERENCES public.transfers(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  ip_address TEXT,
  trust_delta INT NOT NULL DEFAULT 0,
  simulated BOOLEAN NOT NULL DEFAULT false,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 12. THREAT INCIDENTS (Dynamic Threat Defense Response)
CREATE TABLE IF NOT EXISTS public.threat_incidents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id REFERENCES auth.users(id) ON DELETE SET NULL,
  transfer_id UUID REFERENCES public.transfers(id) ON DELETE SET NULL,
  threat_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  action_taken TEXT NOT NULL,
  trust_delta INT NOT NULL DEFAULT 0,
  blocked BOOLEAN NOT NULL DEFAULT true,
  simulated BOOLEAN NOT NULL DEFAULT false,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  resolved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 13. AUDIT LOGS (Immutable System Activity Log)
CREATE TABLE IF NOT EXISTS public.audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  transfer_id UUID REFERENCES public.transfers(id) ON DELETE SET NULL,
  event TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  ip_address TEXT,
  action TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 14. NOTIFICATIONS (User Alert Notifications)
CREATE TABLE IF NOT EXISTS public.notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  transfer_id UUID REFERENCES public.transfers(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  read BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 15. TRUST EVENTS (Persistent Trust Mutation History)
CREATE TABLE IF NOT EXISTS public.trust_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  security_event_id UUID REFERENCES public.security_events(id) ON DELETE SET NULL,
  previous_score INT NOT NULL,
  delta INT NOT NULL,
  new_score INT NOT NULL,
  reason TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ==============================================================================
-- HELPER FUNCTIONS & TRIGGERS
-- ==============================================================================

CREATE OR REPLACE FUNCTION public.has_role(_user_id UUID, _role public.app_role)
RETURNS BOOLEAN LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role);
$$;

CREATE OR REPLACE FUNCTION public.get_public_key(_user_id UUID)
RETURNS JSONB LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT public_key_jwk FROM public.user_keys WHERE user_id = _user_id;
$$;

CREATE OR REPLACE FUNCTION public.users_with_published_keys()
RETURNS TABLE (user_id UUID) LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT k.user_id FROM public.user_keys k;
$$;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql SET search_path = public AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS transfers_updated_at ON public.transfers;
CREATE TRIGGER transfers_updated_at BEFORE UPDATE ON public.transfers FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

DROP TRIGGER IF EXISTS profiles_updated_at ON public.profiles;
CREATE TRIGGER profiles_updated_at BEFORE UPDATE ON public.profiles FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, trust_score, trust_status)
  VALUES (
    NEW.id,
    COALESCE(NEW.email, ''),
    NEW.raw_user_meta_data->>'full_name',
    100,
    'TRUSTED'
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    full_name = COALESCE(EXCLUDED.full_name, profiles.full_name);

  INSERT INTO public.user_roles (user_id, role)
  VALUES (NEW.id, 'user')
  ON CONFLICT DO NOTHING;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transfers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.transfer_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.threat_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.trust_events ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select_all_authenticated" ON public.profiles;
CREATE POLICY "profiles_select_all_authenticated" ON public.profiles FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "profiles_update_own" ON public.profiles;
CREATE POLICY "profiles_update_own" ON public.profiles FOR UPDATE TO authenticated USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_admin_update" ON public.profiles;
CREATE POLICY "profiles_admin_update" ON public.profiles FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "profiles_insert_own" ON public.profiles;
CREATE POLICY "profiles_insert_own" ON public.profiles FOR INSERT TO authenticated WITH CHECK (auth.uid() = id);

DROP POLICY IF EXISTS "user_roles_select_own" ON public.user_roles;
CREATE POLICY "user_roles_select_own" ON public.user_roles FOR SELECT TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "user_keys_select_own" ON public.user_keys;
CREATE POLICY "user_keys_select_own" ON public.user_keys FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "user_keys_write_own" ON public.user_keys;
CREATE POLICY "user_keys_write_own" ON public.user_keys FOR INSERT TO authenticated WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "user_keys_update_own" ON public.user_keys;
CREATE POLICY "user_keys_update_own" ON public.user_keys FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "devices_own" ON public.devices;
CREATE POLICY "devices_own" ON public.devices FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin')) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "app_sessions_own" ON public.app_sessions;
CREATE POLICY "app_sessions_own" ON public.app_sessions FOR ALL TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin')) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "transfers_party_select" ON public.transfers;
CREATE POLICY "transfers_party_select" ON public.transfers FOR SELECT TO authenticated
  USING (auth.uid() = sender_id OR auth.uid() = recipient_id OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "transfer_keys_party_select" ON public.transfer_keys;
CREATE POLICY "transfer_keys_party_select" ON public.transfer_keys FOR SELECT TO authenticated USING (
  EXISTS (SELECT 1 FROM public.transfers t WHERE t.id = transfer_id AND (t.sender_id = auth.uid() OR t.recipient_id = auth.uid() OR public.has_role(auth.uid(), 'admin')))
);

DROP POLICY IF EXISTS "file_metadata_party_select" ON public.file_metadata;
CREATE POLICY "file_metadata_party_select" ON public.file_metadata FOR SELECT TO authenticated USING (
  EXISTS (SELECT 1 FROM public.transfers t WHERE t.id = transfer_id AND (t.sender_id = auth.uid() OR t.recipient_id = auth.uid() OR public.has_role(auth.uid(), 'admin')))
);

DROP POLICY IF EXISTS "security_events_own" ON public.security_events;
CREATE POLICY "security_events_own" ON public.security_events FOR SELECT TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "threat_incidents_own" ON public.threat_incidents;
CREATE POLICY "threat_incidents_own" ON public.threat_incidents FOR SELECT TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "audit_logs_own" ON public.audit_logs;
CREATE POLICY "audit_logs_own" ON public.audit_logs FOR SELECT TO authenticated USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "audit_logs_transfer_party_select" ON public.audit_logs;
CREATE POLICY "audit_logs_transfer_party_select" ON public.audit_logs FOR SELECT TO authenticated
  USING (
    transfer_id IS NOT NULL AND EXISTS (
      SELECT 1 FROM public.transfers t
      WHERE t.id = audit_logs.transfer_id
        AND (t.sender_id = auth.uid() OR t.recipient_id = auth.uid())
    )
  );

DROP POLICY IF EXISTS "notifications_own" ON public.notifications;
CREATE POLICY "notifications_own" ON public.notifications FOR SELECT TO authenticated USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "notifications_own_update" ON public.notifications;
CREATE POLICY "notifications_own_update" ON public.notifications FOR UPDATE TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS "trust_events_select_own" ON public.trust_events;
CREATE POLICY "trust_events_select_own" ON public.trust_events FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

-- Revoke dangerous privileges
REVOKE ALL ON public.profiles, public.user_keys, public.user_roles, public.devices,
  public.app_sessions, public.transfers, public.transfer_keys, public.file_metadata,
  public.security_events, public.threat_incidents, public.audit_logs, public.notifications,
  public.trust_events FROM anon;

REVOKE ALL ON FUNCTION public.handle_new_user() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.set_updated_at() FROM PUBLIC, anon, authenticated;
REVOKE ALL ON FUNCTION public.has_role(uuid, public.app_role) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.get_public_key(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_public_key(uuid) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.users_with_published_keys() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.users_with_published_keys() TO authenticated, service_role;

-- Grant fine-grained permissions
GRANT SELECT, INSERT ON public.profiles TO authenticated;
GRANT UPDATE (full_name, organization, updated_at) ON public.profiles TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.user_keys TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.devices TO authenticated;
GRANT SELECT, INSERT, UPDATE ON public.app_sessions TO authenticated;
GRANT SELECT ON public.transfers TO authenticated;
GRANT SELECT ON public.transfer_keys TO authenticated;
GRANT SELECT ON public.file_metadata TO authenticated;
GRANT SELECT ON public.security_events TO authenticated;
GRANT SELECT ON public.threat_incidents TO authenticated;
GRANT SELECT ON public.audit_logs TO authenticated;
GRANT SELECT ON public.trust_events TO authenticated;
GRANT SELECT, UPDATE (read) ON public.notifications TO authenticated;

GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT ALL ON ALL ROUTINES IN SCHEMA public TO service_role;

-- Storage setup
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('encrypted-payloads', 'encrypted-payloads', false, 52428800)
ON CONFLICT (id) DO UPDATE SET
  public = false,
  file_size_limit = 52428800;

DROP POLICY IF EXISTS "encrypted_payloads_sender_insert" ON storage.objects;
CREATE POLICY "encrypted_payloads_sender_insert" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS "encrypted_payloads_owner_select" ON storage.objects;
CREATE POLICY "encrypted_payloads_owner_select" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_transfers_sender ON public.transfers(sender_id);
CREATE INDEX IF NOT EXISTS idx_transfers_recipient ON public.transfers(recipient_id);
CREATE INDEX IF NOT EXISTS idx_transfers_status ON public.transfers(status);
CREATE INDEX IF NOT EXISTS idx_audit_user ON public.audit_logs(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_user ON public.security_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_user ON public.threat_incidents(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_trust_events_user ON public.trust_events(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON public.notifications(user_id, read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_app_sessions_user ON public.app_sessions(user_id, revoked, expires_at DESC);
