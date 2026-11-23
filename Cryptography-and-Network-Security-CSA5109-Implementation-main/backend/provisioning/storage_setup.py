from .supabase_manager import SupabaseManager


STORAGE_SETUP_SQL = """
-- Ensure private storage bucket exists
INSERT INTO storage.buckets (id, name, public, file_size_limit)
VALUES ('encrypted-payloads', 'encrypted-payloads', false, 52428800)
ON CONFLICT (id) DO UPDATE SET
  public = false,
  file_size_limit = 52428800;

-- Storage policies
DROP POLICY IF EXISTS "encrypted_payloads_sender_insert" ON storage.objects;
CREATE POLICY "encrypted_payloads_sender_insert" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);

DROP POLICY IF EXISTS "encrypted_payloads_owner_select" ON storage.objects;
CREATE POLICY "encrypted_payloads_owner_select" ON storage.objects FOR SELECT TO authenticated
USING (bucket_id = 'encrypted-payloads' AND (storage.foldername(name))[1] = auth.uid()::text);
"""


async def configure_storage_bucket(
    manager: SupabaseManager,
    project_ref: str,
) -> bool:
    """Configures the private encrypted-payloads bucket and RLS policies."""
    print(f"[storage_setup] Configuring storage bucket on project '{project_ref}'...")
    try:
        await manager.execute_sql(project_ref, STORAGE_SETUP_SQL)
        print("[storage_setup] Private bucket 'encrypted-payloads' configured successfully.")
        return True
    except Exception as e:
        print(f"[storage_setup] Error configuring storage: {e}")
        raise
