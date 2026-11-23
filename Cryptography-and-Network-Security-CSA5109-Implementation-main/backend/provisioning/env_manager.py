import os
import shutil
from pathlib import Path
from typing import Dict, Optional


def find_project_root() -> Path:
    """Finds the root directory of the project by looking for package.json."""
    current = Path(__file__).resolve().parent
    while current.parent != current:
        if (current / "package.json").exists() and (current / "src").exists():
            return current
        current = current.parent
    # Fallback to current working directory
    return Path.cwd()


def get_env_path() -> Path:
    return find_project_root() / ".env"


def get_env_backup_path() -> Path:
    return find_project_root() / ".env.backup"


def backup_env_file() -> Optional[Path]:
    """Creates a backup of the existing .env file if it exists."""
    env_file = get_env_path()
    if env_file.exists():
        backup_file = get_env_backup_path()
        shutil.copy2(env_file, backup_file)
        return backup_file
    return None


def read_existing_env() -> Dict[str, str]:
    """Reads existing environment variables from the .env file."""
    env_file = get_env_path()
    if not env_file.exists():
        return {}

    env_vars: Dict[str, str] = {}
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                env_vars[key] = val
    except Exception as e:
        print(f"[env_manager] Warning reading .env: {e}")
    return env_vars


def write_supabase_env(
    project_ref: str,
    project_url: str,
    publishable_key: str,
    secret_key: str,
) -> bool:
    """
    Safely writes Supabase credentials to .env file.
    Creates a backup first, preserves any unrelated variables, and guarantees
    correct variable naming for both server and browser clients.
    """
    backup_env_file()
    existing = read_existing_env()

    # Update with new values
    existing["SUPABASE_PROJECT_ID"] = project_ref
    existing["SUPABASE_URL"] = project_url
    existing["SUPABASE_PUBLISHABLE_KEY"] = publishable_key
    existing["SUPABASE_SECRET_KEY"] = secret_key

    # Public client variables (VITE_ prefixed)
    existing["VITE_SUPABASE_PROJECT_ID"] = project_ref
    existing["VITE_SUPABASE_URL"] = project_url
    existing["VITE_SUPABASE_PUBLISHABLE_KEY"] = publishable_key

    env_content = f"""# ==============================================================================
# SENTINELCRYPT SUPABASE CONFIGURATION
# Generated automatically by SentinelCrypt Provisioning Engine
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. Server-Side Privileged Credentials (NEVER expose to browser)
# ------------------------------------------------------------------------------
SUPABASE_PROJECT_ID="{project_ref}"
SUPABASE_URL="{project_url}"
SUPABASE_PUBLISHABLE_KEY="{publishable_key}"
SUPABASE_SECRET_KEY="{secret_key}"

# ------------------------------------------------------------------------------
# 2. Client-Side Public Credentials (VITE_ prefixed)
# ------------------------------------------------------------------------------
VITE_SUPABASE_PROJECT_ID="{project_ref}"
VITE_SUPABASE_URL="{project_url}"
VITE_SUPABASE_PUBLISHABLE_KEY="{publishable_key}"
"""

    # Append any extra existing variables that weren't Supabase-specific
    extra_vars = {
        k: v
        for k, v in existing.items()
        if not k.startswith("SUPABASE_") and not k.startswith("VITE_SUPABASE_")
    }
    if extra_vars:
        env_content += "\n# ------------------------------------------------------------------------------\n# Additional Environment Variables\n# ------------------------------------------------------------------------------\n"
        for k, v in extra_vars.items():
            env_content += f'{k}="{v}"\n'

    env_path = get_env_path()
    with open(env_path, "w", encoding="utf-8") as f:
        f.write(env_content)

    return True


def ensure_gitignore_protection() -> None:
    """Ensures .gitignore ignores .env and .env.backup while keeping .env.example."""
    gitignore_path = find_project_root() / ".gitignore"
    if not gitignore_path.exists():
        return

    try:
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        required_entries = [".env", ".env.*", "!.env.example"]
        missing_entries = [entry for entry in required_entries if entry not in content]

        if missing_entries:
            with open(gitignore_path, "a", encoding="utf-8") as f:
                f.write("\n# Environment configuration\n")
                for entry in missing_entries:
                    f.write(f"{entry}\n")
    except Exception as e:
        print(f"[env_manager] Warning updating .gitignore: {e}")
