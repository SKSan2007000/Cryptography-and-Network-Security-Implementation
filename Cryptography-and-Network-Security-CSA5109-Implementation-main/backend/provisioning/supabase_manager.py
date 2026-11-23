import os
import secrets
import string
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx

from .models import OrganizationModel, ProjectModel


SUPABASE_API_BASE = "https://api.supabase.com/v1"


def generate_secure_db_password(length: int = 24) -> str:
    """Generates a high-entropy database password satisfying Supabase requirements."""
    alphabet = string.ascii_letters + string.digits + "!#$%&*+-=?@^_"
    # Ensure at least one uppercase, lowercase, digit, and special char
    password = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!#$%&*+-=?@^_"),
    ]
    password += [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password)
    return "".join(password)


class SupabaseManager:
    """Client for the official Supabase Management API."""

    def __init__(self, token: Optional[str] = None):
        raw_token = token or os.getenv("SUPABASE_MANAGEMENT_ACCESS_TOKEN")
        if raw_token:
            # Thoroughly strip leading/trailing whitespace, newlines, tabs, and quotes
            cleaned = str(raw_token).strip().strip('"').strip("'").strip()
            if cleaned.startswith("Bearer "):
                cleaned = cleaned[7:].strip()
            self.token = cleaned
        else:
            self.token = ""

        if not self.token:
            raise ValueError(
                "Missing SUPABASE_MANAGEMENT_ACCESS_TOKEN. "
                "Please generate a Management API Access Token at https://app.supabase.com/account/tokens "
                "and set it as an environment variable or pass it to the provisioning service."
            )

    @property
    def headers(self) -> Dict[str, str]:
        # Exactly "Bearer <PAT>" with zero leading or trailing whitespace
        auth_header = f"Bearer {self.token}".strip()
        return {
            "Authorization": auth_header,
            "Content-Type": "application/json",
            "User-Agent": "SentinelCrypt-Provisioner/1.0",
        }

    async def list_organizations(self) -> List[OrganizationModel]:
        """Lists all organizations accessible by the authenticated account."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{SUPABASE_API_BASE}/organizations", headers=self.headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Failed to list organizations from Supabase Management API (HTTP {resp.status_code}): {resp.text}"
                )
            data = resp.json()
            return [OrganizationModel(id=org["id"], name=org["name"]) for org in data]

    async def list_projects(self) -> List[ProjectModel]:
        """Lists all projects accessible by the authenticated account."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{SUPABASE_API_BASE}/projects", headers=self.headers)
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Failed to list projects from Supabase Management API (HTTP {resp.status_code}): {resp.text}"
                )
            data = resp.json()
            return [
                ProjectModel(
                    id=proj.get("id", proj.get("ref", "")),
                    ref=proj.get("ref", proj.get("id", "")),
                    name=proj.get("name", "Untitled"),
                    region=proj.get("region", "unknown"),
                    status=proj.get("status", "UNKNOWN"),
                    created_at=proj.get("created_at"),
                )
                for proj in data
            ]

    async def find_existing_project(self, project_name: str) -> Optional[ProjectModel]:
        """Searches for an existing project matching the given name."""
        projects = await self.list_projects()
        for proj in projects:
            if proj.name.lower() == project_name.lower():
                return proj
        return None

    async def create_project(
        self,
        name: str,
        organization_id: str,
        region: str = "us-east-1",
        db_password: Optional[str] = None,
    ) -> Tuple[ProjectModel, str]:
        """
        Creates a new Supabase cloud project using the Management API.
        Returns the project model and the database password.
        """
        password = db_password or generate_secure_db_password(24)

        payload = {
            "name": name,
            "organization_id": organization_id,
            "region": region,
            "db_pass": password,
            "plan": "free",
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            resp = await client.post(
                f"{SUPABASE_API_BASE}/projects",
                headers=self.headers,
                json=payload,
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"Failed to create Supabase project (HTTP {resp.status_code}): {resp.text}"
                )

            data = resp.json()
            project = ProjectModel(
                id=data.get("id", data.get("ref", "")),
                ref=data.get("ref", data.get("id", "")),
                name=data.get("name", name),
                region=data.get("region", region),
                status=data.get("status", "COMING_UP"),
            )
            return project, password

    async def get_project_status(self, project_ref: str) -> ProjectModel:
        """Fetches the current status and metadata of a project."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SUPABASE_API_BASE}/projects/{project_ref}",
                headers=self.headers,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Failed to get project status for {project_ref} (HTTP {resp.status_code}): {resp.text}"
                )

            data = resp.json()
            return ProjectModel(
                id=data.get("id", project_ref),
                ref=data.get("ref", project_ref),
                name=data.get("name", "SentinelCrypt"),
                region=data.get("region", "unknown"),
                status=data.get("status", "UNKNOWN"),
                created_at=data.get("created_at"),
            )

    async def poll_until_ready(
        self,
        project_ref: str,
        max_wait_seconds: int = 300,
        poll_interval_seconds: int = 5,
    ) -> ProjectModel:
        """Polls until the project status is ACTIVE_HEALTHY or timeout is reached."""
        start_time = time.time()
        while time.time() - start_time < max_wait_seconds:
            proj = await self.get_project_status(project_ref)
            if proj.status in ("ACTIVE_HEALTHY", "READY", "ACTIVE"):
                return proj
            if "FAILED" in proj.status.upper():
                raise RuntimeError(f"Project creation failed with status: {proj.status}")
            time.sleep(poll_interval_seconds)

        raise TimeoutError(
            f"Timed out after {max_wait_seconds}s waiting for project {project_ref} to become active. "
            "The project is still initializing in the cloud."
        )

    async def get_project_api_keys(self, project_ref: str) -> Dict[str, str]:
        """
        Retrieves the publishable (anon) and secret (service_role) API keys
        from the official Supabase Management API.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{SUPABASE_API_BASE}/projects/{project_ref}/api-keys",
                headers=self.headers,
            )
            if resp.status_code != 200:
                raise RuntimeError(
                    f"Failed to fetch API keys for project {project_ref} (HTTP {resp.status_code}): {resp.text}"
                )

            keys_list = resp.json()
            keys_dict: Dict[str, str] = {}
            for item in keys_list:
                name = item.get("name")
                api_key = item.get("api_key")
                if name and api_key:
                    keys_dict[name] = api_key

            anon_key = keys_dict.get("anon")
            service_role_key = keys_dict.get("service_role")

            if not anon_key or not service_role_key:
                raise RuntimeError(
                    f"Supabase API key response missing anon or service_role key: {list(keys_dict.keys())}"
                )

            return {
                "anon": anon_key,
                "service_role": service_role_key,
                "project_url": f"https://{project_ref}.supabase.co",
            }

    async def execute_sql(self, project_ref: str, sql_query: str) -> Any:
        """
        Executes a raw SQL query against the Supabase database
        using the Supabase Management API database query endpoint.
        """
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{SUPABASE_API_BASE}/projects/{project_ref}/database/query",
                headers=self.headers,
                json={"query": sql_query},
            )
            if resp.status_code not in (200, 201):
                raise RuntimeError(
                    f"Failed to execute SQL query on project {project_ref} (HTTP {resp.status_code}): {resp.text}"
                )
            return resp.json()
