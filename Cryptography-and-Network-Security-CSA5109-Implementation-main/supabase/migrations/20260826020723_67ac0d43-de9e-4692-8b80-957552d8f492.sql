CREATE OR REPLACE FUNCTION public.users_with_published_keys()
RETURNS TABLE (user_id uuid)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT k.user_id FROM public.user_keys k;
$$;
REVOKE ALL ON FUNCTION public.users_with_published_keys() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.users_with_published_keys() TO authenticated, service_role;