from pathlib import Path
from typing import Optional
from .env_manager import find_project_root
from .supabase_manager import SupabaseManager


def load_schema_sql(schema_file_path: Optional[str] = None) -> str:
    """Loads the SQL schema text from supabase/schema.sql or specified file."""
    root = find_project_root()
    if schema_file_path:
        target = Path(schema_file_path)
        if not target.is_absolute():
            target = root / target
    else:
        target = root / "supabase" / "schema.sql"

    if not target.exists():
        # Fallback to migrations directory
        migration_file = root / "supabase" / "migrations" / "20260907120000_complete_sentinelcrypt_schema.sql"
        if migration_file.exists():
            target = migration_file
        else:
            raise FileNotFoundError(f"Could not locate schema SQL file at {target}")

    with open(target, "r", encoding="utf-8") as f:
        return f.read()


async def apply_complete_schema(
    manager: SupabaseManager,
    project_ref: str,
    schema_file_path: Optional[str] = None,
) -> bool:
    """Executes the full idempotent schema against the Supabase project."""
    sql = load_schema_sql(schema_file_path)
    print(f"[schema_runner] Applying complete database schema to project '{project_ref}'...")
    try:
        await manager.execute_sql(project_ref, sql)
        print("[schema_runner] Database schema applied successfully.")
        return True
    except Exception as e:
        print(f"[schema_runner] Error applying schema: {e}")
        raise
