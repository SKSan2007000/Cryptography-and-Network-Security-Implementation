import argparse
import asyncio
import os
import sys
import uvicorn

from .env_manager import write_supabase_env, ensure_gitignore_protection
from .models import ProjectModel
from .schema_runner import apply_complete_schema
from .storage_setup import configure_storage_bucket
from .supabase_manager import SupabaseManager
from .verifier import verify_backend


def print_banner():
    print("=" * 70)
    print("   SENTINELCRYPT — AUTOMATED SUPABASE PROVISIONING ENGINE")
    print("=" * 70)


async def run_provisioning_cli(args):
    print_banner()

    token = args.token or os.getenv("SUPABASE_MANAGEMENT_ACCESS_TOKEN")
    if not token:
        print("\n[!] SUPABASE_MANAGEMENT_ACCESS_TOKEN is required.")
        print("    1. Go to https://app.supabase.com/account/tokens")
        print("    2. Generate a Personal Access Token with project create/write permissions.")
        print("    3. Either:")
        print("       - Run: $env:SUPABASE_MANAGEMENT_ACCESS_TOKEN=\"your_token\"; python -m backend.provisioning")
        print("       - Or:  python -m backend.provisioning --token \"your_token\"\n")
        sys.exit(1)

    manager = SupabaseManager(token=token)

    try:
        # 1. Check organizations
        print("\n[*] Step 1/7: Fetching Supabase account organizations...")
        orgs = await manager.list_organizations()
        if not orgs:
            print("[x] Error: No organizations found on your Supabase account.")
            sys.exit(1)
        target_org = orgs[0]
        print(f"    Selected organization: {target_org.name} ({target_org.id})")

        # 2. Check or create project
        print(f"\n[*] Step 2/7: Checking existing projects for '{args.name}'...")
        target_project = None
        if not args.force_new:
            existing = await manager.find_existing_project(args.name)
            if existing:
                print(f"    Found existing project '{existing.name}' [{existing.ref}] in {existing.region}. Reusing.")
                target_project = existing

        if not target_project:
            print(f"    Creating new cloud project '{args.name}' in region '{args.region}'...")
            target_project, _ = await manager.create_project(
                name=args.name,
                organization_id=target_org.id,
                region=args.region,
            )
            print(f"    Project requested with Ref: {target_project.ref}")

        # 3. Wait for READY status
        print(f"\n[*] Step 3/7: Waiting for project '{target_project.ref}' to become active...")
        ready_project = await manager.poll_until_ready(target_project.ref, max_wait_seconds=300)
        print(f"    Project is READY (Status: {ready_project.status})")

        # 4. Fetch API Keys
        print(f"\n[*] Step 4/7: Retrieving project API keys from Management API...")
        keys = await manager.get_project_api_keys(ready_project.ref)
        print(f"    Project URL: {keys['project_url']}")
        print(f"    Anon Publishable Key: Retrieved ({keys['anon'][:12]}...)")
        print(f"    Service Role Secret Key: Retrieved [REDACTED]")

        # 5. Apply complete database schema & RLS
        print(f"\n[*] Step 5/7: Applying complete SentinelCrypt database schema & RLS...")
        await apply_complete_schema(manager, ready_project.ref)
        print("    All 13 tables, helper functions, triggers, and RLS policies created.")

        # 6. Configure Storage
        print(f"\n[*] Step 6/7: Configuring private storage bucket 'encrypted-payloads'...")
        await configure_storage_bucket(manager, ready_project.ref)
        print("    Private storage bucket configured with upload & download access policies.")

        # 7. Write Environment & Verify
        print(f"\n[*] Step 7/7: Updating local environment configuration & running verification...")
        write_supabase_env(
            project_ref=ready_project.ref,
            project_url=keys["project_url"],
            publishable_key=keys["anon"],
            secret_key=keys["service_role"],
        )
        ensure_gitignore_protection()
        print("    Local .env file created and backed up to .env.backup.")

        verification = await verify_backend(manager, ready_project.ref)

        print("\n" + "=" * 70)
        print("   SUPABASE PROVISIONING SUMMARY")
        print("=" * 70)
        print(f"Project Name:    {ready_project.name}")
        print(f"Project Ref:     {ready_project.ref}")
        print(f"Region:          {ready_project.region}")
        print(f"Status:          {ready_project.status}")
        print(f"Tables Found:    {len(verification.tables_found)}/13 ({', '.join(verification.tables_found[:6])}...)")
        print(f"Missing Tables:  {len(verification.missing_tables)}")
        print(f"Storage Bucket:  {'READY (Private)' if verification.storage_bucket_exists and verification.is_bucket_private else 'FAILED'}")
        print(f"RLS Protection:  {len(verification.rls_enabled_tables)} tables protected")
        print(f"Environment:     CONFIGURED (.env)")
        print(f"Overall Status:  {'SUCCESS — READY FOR USE' if verification.is_ready else 'INCOMPLETE'}")
        print("=" * 70)
        print("\nYou can now start the application with:")
        print("  npm run dev\n")

    except Exception as e:
        print(f"\n[x] Provisioning failed: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Automated Supabase Provisioning for SentinelCrypt")
    parser.add_argument("--token", help="Supabase Management API Access Token")
    parser.add_argument("--name", default="SentinelCrypt", help="Project name (default: SentinelCrypt)")
    parser.add_argument("--region", default="us-east-1", help="Supabase AWS Region (default: us-east-1)")
    parser.add_argument("--force-new", action="store_true", help="Force creating a new project even if name exists")
    parser.add_argument("--server", action="store_true", help="Start the FastAPI provisioning server on port 8000")
    parser.add_argument("--port", type=int, default=8000, help="Port for FastAPI server (default: 8000)")
    parser.add_argument("--host", default="127.0.0.1", help="Host for FastAPI server (default: 127.0.0.1)")

    args = parser.parse_args()

    if args.server:
        print(f"Starting SentinelCrypt Provisioning Server on http://{args.host}:{args.port}")
        uvicorn.run("backend.provisioning.main:app", host=args.host, port=args.port, reload=False)
    else:
        asyncio.run(run_provisioning_cli(args))


if __name__ == "__main__":
    main()
