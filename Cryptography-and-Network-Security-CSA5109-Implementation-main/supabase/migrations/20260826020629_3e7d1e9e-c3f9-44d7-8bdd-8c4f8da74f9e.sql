-- 1. user_keys: stop exposing every user's wrapped private key material.
DROP POLICY IF EXISTS user_keys_select_authenticated ON public.user_keys;
CREATE POLICY user_keys_select_own ON public.user_keys
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id);

-- Public RSA-OAEP public keys are exposed through a narrow security-definer function.
CREATE OR REPLACE FUNCTION public.get_public_key(_user_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public_key_jwk FROM public.user_keys WHERE user_id = _user_id;
$$;
REVOKE ALL ON FUNCTION public.get_public_key(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.get_public_key(uuid) TO authenticated, service_role;

-- 2. Transfer state is owned by the server threat/transfer engine only.
DROP POLICY IF EXISTS transfers_party_update ON public.transfers;
DROP POLICY IF EXISTS transfers_sender_insert ON public.transfers;
DROP POLICY IF EXISTS transfer_keys_sender_insert ON public.transfer_keys;
DROP POLICY IF EXISTS file_metadata_sender_insert ON public.file_metadata;
REVOKE INSERT, UPDATE, DELETE ON public.transfers FROM authenticated, anon;
REVOKE INSERT, UPDATE, DELETE ON public.transfer_keys FROM authenticated, anon;
REVOKE INSERT, UPDATE, DELETE ON public.file_metadata FROM authenticated, anon;

-- 3. Users must not be able to rewrite their own trust score or account status.
REVOKE UPDATE ON public.profiles FROM authenticated, anon;
GRANT UPDATE (full_name, organization, updated_at) ON public.profiles TO authenticated;

-- 4. Append-only security telemetry: no client writes at all.
REVOKE INSERT, UPDATE, DELETE ON public.audit_logs FROM authenticated, anon;
REVOKE INSERT, UPDATE, DELETE ON public.security_events FROM authenticated, anon;
REVOKE INSERT, UPDATE, DELETE ON public.threat_incidents FROM authenticated, anon;
REVOKE INSERT, DELETE ON public.notifications FROM authenticated, anon;
REVOKE UPDATE ON public.notifications FROM authenticated, anon;
GRANT UPDATE (read) ON public.notifications TO authenticated;

-- 5. Anonymous role has no business with any of these tables.
REVOKE ALL ON public.profiles, public.user_keys, public.user_roles, public.devices,
  public.app_sessions, public.transfers, public.transfer_keys, public.file_metadata,
  public.security_events, public.threat_incidents, public.audit_logs, public.notifications
  FROM anon;

-- 6. Users may not delete their own audit-relevant session/device history.
REVOKE DELETE ON public.app_sessions, public.devices FROM authenticated;