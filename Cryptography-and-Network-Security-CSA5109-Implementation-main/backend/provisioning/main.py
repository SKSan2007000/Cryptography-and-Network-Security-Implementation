import os
from fastapi import FastAPI, HTTPException, Header, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional

from .models import (
    ApplySchemaRequest,
    ConfigureStorageRequest,
    OrganizationModel,
    ProjectModel,
    ProvisionRequest,
    ProvisionResponse,
    VerificationResult,
)
from .supabase_manager import SupabaseManager
from .schema_runner import apply_complete_schema
from .storage_setup import configure_storage_bucket
from .env_manager import write_supabase_env, ensure_gitignore_protection, read_existing_env
from .verifier import verify_backend


app = FastAPI(
    title="SentinelCrypt Supabase Provisioning Engine",
    description="Automated FastAPI service for provisioning and configuring Supabase backends for SentinelCrypt.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_manager(token: Optional[str] = None) -> SupabaseManager:
    try:
        return SupabaseManager(token=token)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@app.get("/health")
async def health_check():
    env = read_existing_env()
    has_project = bool(env.get("SUPABASE_PROJECT_ID"))
    has_secret = bool(env.get("SUPABASE_SECRET_KEY") or env.get("SUPABASE_SERVICE_ROLE_KEY"))
    has_mgmt_token = bool(os.getenv("SUPABASE_MANAGEMENT_ACCESS_TOKEN"))

    return {
        "status": "ok",
        "service": "SentinelCrypt Provisioning Engine",
        "management_token_configured": has_mgmt_token,
        "supabase_project_configured": has_project,
        "supabase_secret_key_configured": has_secret,
    }


@app.get("/provision/organizations", response_model=list[OrganizationModel])
async def list_organizations(
    authorization: Optional[str] = Header(None),
):
    token = authorization.replace("Bearer ", "") if authorization else None
    manager = get_manager(token)
    try:
        return await manager.list_organizations()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/provision/projects", response_model=list[ProjectModel])
async def list_projects(
    authorization: Optional[str] = Header(None),
):
    token = authorization.replace("Bearer ", "") if authorization else None
    manager = get_manager(token)
    try:
        return await manager.list_projects()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/provision/supabase", response_model=ProvisionResponse)
async def provision_supabase(
    req: ProvisionRequest,
    authorization: Optional[str] = Header(None),
):
    """
    Executes the complete, end-to-end Supabase automated provisioning:
    1. Authenticate with Management API
    2. Check existing projects or create a new project
    3. Wait until project is ACTIVE
    4. Fetch API keys
    5. Apply database schema & RLS policies
    6. Configure private storage bucket
    7. Write .env safely
    8. Verify setup
    """
    token = req.management_token or (authorization.replace("Bearer ", "") if authorization else None)
    manager = get_manager(token)

    try:
        target_project: Optional[ProjectModel] = None

        if not req.force_new:
            existing = await manager.find_existing_project(req.project_name)
            if existing:
                print(f"[main] Found existing project '{existing.name}' ({existing.ref}). Reusing project.")
                target_project = existing

        if not target_project:
            # Must create a new project
            orgs = await manager.list_organizations()
            if not orgs:
                raise HTTPException(
                    status_code=400,
                    detail="No Supabase organizations found for this account. Create an organization in Supabase first.",
                )
            org_id = req.organization_id or orgs[0].id

            print(f"[main] Creating new Supabase project '{req.project_name}' in region '{req.region}'...")
            target_project, _ = await manager.create_project(
                name=req.project_name,
                organization_id=org_id,
                region=req.region,
                db_password=req.db_password,
            )

        # Wait until project is ready
        print(f"[main] Polling project '{target_project.ref}' readiness...")
        ready_project = await manager.poll_until_ready(target_project.ref)

        # Fetch API credentials
        print(f"[main] Retrieving API credentials for '{ready_project.ref}'...")
        keys = await manager.get_project_api_keys(ready_project.ref)

        # Apply complete schema & RLS
        print(f"[main] Applying schema to '{ready_project.ref}'...")
        await apply_complete_schema(manager, ready_project.ref)

        # Configure storage
        print(f"[main] Configuring storage bucket on '{ready_project.ref}'...")
        await configure_storage_bucket(manager, ready_project.ref)

        # Write .env configuration safely
        print(f"[main] Updating local environment configuration...")
        env_updated = write_supabase_env(
            project_ref=ready_project.ref,
            project_url=keys["project_url"],
            publishable_key=keys["anon"],
            secret_key=keys["service_role"],
        )
        ensure_gitignore_protection()

        # Run verification
        print(f"[main] Verifying backend...")
        verification = await verify_backend(manager, ready_project.ref)

        return ProvisionResponse(
            success=True,
            message="Supabase backend successfully provisioned and connected to SentinelCrypt.",
            project_name=ready_project.name,
            project_ref=ready_project.ref,
            region=ready_project.region,
            status=ready_project.status,
            env_file_updated=env_updated,
            verification=verification,
        )

    except Exception as e:
        print(f"[main] Provisioning error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/provision/apply-schema")
async def api_apply_schema(
    req: ApplySchemaRequest,
    authorization: Optional[str] = Header(None),
):
    token = req.management_token or (authorization.replace("Bearer ", "") if authorization else None)
    manager = get_manager(token)
    try:
        ok = await apply_complete_schema(manager, req.project_ref, req.schema_file)
        return {"success": ok, "project_ref": req.project_ref}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/provision/configure-storage")
async def api_configure_storage(
    req: ConfigureStorageRequest,
    authorization: Optional[str] = Header(None),
):
    token = req.management_token or (authorization.replace("Bearer ", "") if authorization else None)
    manager = get_manager(token)
    try:
        ok = await configure_storage_bucket(manager, req.project_ref)
        return {"success": ok, "project_ref": req.project_ref, "bucket": req.bucket_name}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/provision/verify", response_model=VerificationResult)
async def api_verify(
    project_ref: str,
    management_token: Optional[str] = None,
    authorization: Optional[str] = Header(None),
):
    token = management_token or (authorization.replace("Bearer ", "") if authorization else None)
    manager = get_manager(token)
    try:
        return await verify_backend(manager, project_ref)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
