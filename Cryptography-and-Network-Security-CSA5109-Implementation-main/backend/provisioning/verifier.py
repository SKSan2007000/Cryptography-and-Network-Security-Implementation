from typing import List
from .models import VerificationResult
from .supabase_manager import SupabaseManager


EXPECTED_TABLES = [
    "profiles",
    "user_roles",
    "user_keys",
    "devices",
    "app_sessions",
    "transfers",
    "transfer_keys",
    "file_metadata",
    "security_events",
    "threat_incidents",
    "audit_logs",
    "notifications",
    "trust_events",
]

VERIFICATION_SQL = """
SELECT
  json_build_object(
    'tables', (
      SELECT COALESCE(json_agg(table_name::text), '[]'::json)
      FROM information_schema.tables
      WHERE table_schema = 'public'
    ),
    'rls_tables', (
      SELECT COALESCE(json_agg(tablename::text), '[]'::json)
      FROM pg_tables
      WHERE schemaname = 'public' AND rowsecurity = true
    ),
    'buckets', (
      SELECT COALESCE(json_agg(json_build_object('id', id, 'public', public)), '[]'::json)
      FROM storage.buckets
      WHERE id = 'encrypted-payloads'
    ),
    'functions', (
      SELECT COALESCE(json_agg(proname::text), '[]'::json)
      FROM pg_proc p
      JOIN pg_namespace n ON p.pronamespace = n.oid
      WHERE n.nspname = 'public'
    )
  ) AS summary;
"""


async def verify_backend(manager: SupabaseManager, project_ref: str) -> VerificationResult:
    """Verifies that all required tables, RLS policies, functions, and storage bucket exist."""
    print(f"[verifier] Verifying backend configuration for project '{project_ref}'...")
    try:
        res = await manager.execute_sql(project_ref, VERIFICATION_SQL)
        # res typically has structure: [{"summary": {...}}] or [[{"summary": ...}]]
        summary = {}
        if isinstance(res, list) and len(res) > 0:
            first_item = res[0]
            if isinstance(first_item, dict) and "summary" in first_item:
                summary = first_item["summary"]
            elif isinstance(first_item, list) and len(first_item) > 0 and isinstance(first_item[0], dict):
                summary = first_item[0].get("summary", {})
        elif isinstance(res, dict) and "summary" in res:
            summary = res["summary"]

        tables_found: List[str] = summary.get("tables", [])
        rls_tables: List[str] = summary.get("rls_tables", [])
        buckets: list = summary.get("buckets", [])
        functions_found: List[str] = summary.get("functions", [])

        missing_tables = [t for t in EXPECTED_TABLES if t not in tables_found]

        storage_bucket_exists = any(b.get("id") == "encrypted-payloads" for b in buckets)
        is_bucket_private = any(
            b.get("id") == "encrypted-payloads" and b.get("public") is False
            for b in buckets
        )

        is_ready = (
            len(missing_tables) == 0
            and storage_bucket_exists
            and is_bucket_private
        )

        return VerificationResult(
            project_ref=project_ref,
            tables_found=tables_found,
            missing_tables=missing_tables,
            storage_bucket_exists=storage_bucket_exists,
            is_bucket_private=is_bucket_private,
            rls_enabled_tables=rls_tables,
            functions_found=functions_found,
            is_ready=is_ready,
            details={"total_tables": len(tables_found), "bucket_count": len(buckets)},
        )
    except Exception as e:
        print(f"[verifier] Error during verification: {e}")
        return VerificationResult(
            project_ref=project_ref,
            tables_found=[],
            missing_tables=EXPECTED_TABLES,
            storage_bucket_exists=False,
            is_bucket_private=False,
            rls_enabled_tables=[],
            functions_found=[],
            is_ready=False,
            details={"error": str(e)},
        )
