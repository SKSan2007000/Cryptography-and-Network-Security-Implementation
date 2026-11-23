from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OrganizationModel(BaseModel):
    id: str
    name: str


class ProjectModel(BaseModel):
    id: str
    ref: str
    name: str
    region: str
    status: str
    created_at: Optional[str] = None


class ProvisionRequest(BaseModel):
    management_token: Optional[str] = Field(
        None,
        description="Supabase Management API access token. If omitted, reads from SUPABASE_MANAGEMENT_ACCESS_TOKEN env.",
    )
    project_name: str = Field(
        default="SentinelCrypt",
        description="Name of the Supabase project to create or select.",
    )
    region: str = Field(
        default="us-east-1",
        description="AWS region for the Supabase project (e.g., us-east-1, eu-west-1, ap-southeast-1).",
    )
    organization_id: Optional[str] = Field(
        None,
        description="Target organization ID. If omitted, uses the first available organization.",
    )
    db_password: Optional[str] = Field(
        None,
        description="Optional custom database password. If omitted, a secure 24-character cryptographic password is automatically generated.",
    )
    force_new: bool = Field(
        default=False,
        description="If True, creates a new project even if an existing project with the same name exists.",
    )


class ApplySchemaRequest(BaseModel):
    management_token: Optional[str] = None
    project_ref: str
    schema_file: Optional[str] = None


class ConfigureStorageRequest(BaseModel):
    management_token: Optional[str] = None
    project_ref: str
    bucket_name: str = "encrypted-payloads"
    is_public: bool = False
    file_size_limit_mb: int = 50


class VerificationResult(BaseModel):
    project_ref: str
    tables_found: List[str]
    missing_tables: List[str]
    storage_bucket_exists: bool
    is_bucket_private: bool
    rls_enabled_tables: List[str]
    functions_found: List[str]
    is_ready: bool
    details: Dict[str, Any] = Field(default_factory=dict)


class ProvisionResponse(BaseModel):
    success: bool
    message: str
    project_name: str
    project_ref: str
    region: str
    status: str
    env_file_updated: bool
    verification: Optional[VerificationResult] = None
