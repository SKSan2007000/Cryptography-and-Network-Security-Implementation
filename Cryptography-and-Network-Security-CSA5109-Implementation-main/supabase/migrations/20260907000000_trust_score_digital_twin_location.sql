-- Migration: Trust Score, Trust Events History, and Transfer Location Telemetry

-- 1. Extend profiles with trust_status and trust_updated_at
ALTER TABLE public.profiles
  ADD COLUMN IF NOT EXISTS trust_status TEXT NOT NULL DEFAULT 'TRUSTED',
  ADD COLUMN IF NOT EXISTS trust_updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- 2. Extend transfers with consent-based geolocation coordinates and timestamps
ALTER TABLE public.transfers
  ADD COLUMN IF NOT EXISTS sender_latitude NUMERIC(9,6),
  ADD COLUMN IF NOT EXISTS sender_longitude NUMERIC(9,6),
  ADD COLUMN IF NOT EXISTS sender_location_timestamp TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS receiver_latitude NUMERIC(9,6),
  ADD COLUMN IF NOT EXISTS receiver_longitude NUMERIC(9,6),
  ADD COLUMN IF NOT EXISTS receiver_location_timestamp TIMESTAMPTZ;

-- 3. Create trust_events audit table
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

GRANT SELECT ON public.trust_events TO authenticated;
GRANT ALL ON public.trust_events TO service_role;
ALTER TABLE public.trust_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "trust_events_select_own" ON public.trust_events
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(), 'admin'));

-- Prevent direct client tampering
REVOKE INSERT, UPDATE, DELETE ON public.trust_events FROM authenticated, anon;
REVOKE ALL ON public.trust_events FROM anon;

CREATE INDEX IF NOT EXISTS idx_trust_events_user ON public.trust_events(user_id, created_at DESC);
