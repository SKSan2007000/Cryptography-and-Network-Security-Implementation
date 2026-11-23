# SentinelCrypt: Supabase Backend Setup Guide

This guide walks you through connecting SentinelCrypt to a new or existing Supabase project.

---

## Step 1: Create a New Supabase Project

1. Go to [https://supabase.com/dashboard](https://supabase.com/dashboard) and sign in.
2. Click **"New project"** and select your organization.
3. Name your project (e.g. `sentinelcrypt-vault`) and set a strong database password.
4. Select your preferred region and click **"Create new project"**.

---

## Step 2: Obtain Project API Keys

Once your project finishes provisioning (usually ~1–2 minutes):

1. In the Supabase dashboard, go to **Project Settings** (gear icon in the sidebar) &rarr; **API**.
2. Copy the following values:
   - **Project URL** (e.g. `https://xyzcompany.supabase.co`)
   - **Project Reference ID** (e.g. `xyzcompany`)
   - **Publishable Key (`anon` / `public`)** (starts with `sb_publishable_` or `eyJ...`)
   - **Secret Key (`service_role` / `secret`)** (starts with `sb_secret_` or `eyJ...`)

> [!CAUTION]
> The **Secret Key** (`service_role` / `sb_secret_*`) bypasses Row Level Security.
>
> - **NEVER** commit your secret key to version control.
> - **NEVER** prefix the secret key with `VITE_` (doing so would expose it in client JavaScript bundles).

---

## Step 3: Configure Environment Variables

Open the `.env` file at the root of your project:

```env
# ==============================================================================
# SUPABASE BACKEND CONFIGURATION (Server-side & Privileged Operations)
# ==============================================================================
SUPABASE_PROJECT_ID="your-project-id"
SUPABASE_URL="https://your-project-id.supabase.co"
SUPABASE_PUBLISHABLE_KEY="your-publishable-key"
SUPABASE_SECRET_KEY="your-secret-key"

# Legacy alias fallback (optional):
# SUPABASE_SERVICE_ROLE_KEY="your-secret-key"

# ==============================================================================
# SUPABASE CLIENT CONFIGURATION (Browser & Public Client)
# ==============================================================================
VITE_SUPABASE_PROJECT_ID="your-project-id"
VITE_SUPABASE_URL="https://your-project-id.supabase.co"
VITE_SUPABASE_PUBLISHABLE_KEY="your-publishable-key"
```

---

## Step 4: Apply Database Schema & Migrations

1. In the Supabase Dashboard, navigate to the **SQL Editor** (terminal icon in left sidebar).
2. Click **"New query"**.
3. Open the file [`supabase/schema.sql`](./supabase/schema.sql) in this repository.
4. Copy its entire content, paste it into the SQL Editor, and click **"Run"** (or press `Ctrl+Enter`).

This will automatically create:

- All 13 core tables (`profiles`, `user_roles`, `user_keys`, `devices`, `app_sessions`, `transfers`, `transfer_keys`, `file_metadata`, `security_events`, `threat_incidents`, `audit_logs`, `notifications`, `trust_events`).
- Constraints (`trust_score` between 0 and 100, valid coordinates, etc.).
- Helper functions and automated triggers (`handle_new_user`, `set_updated_at`, `has_role`, `get_public_key`, `users_with_published_keys`).
- Row Level Security (RLS) policies for user data protection.
- Storage bucket `encrypted-payloads` (private with 50MB file size limit) and upload/download storage policies.
- Performance indexes.

---

## Step 5: (Optional) Promote an Initial Administrator

By default, new users receive the `'user'` role upon registering. If you wish to promote your account to an administrator:

1. Register an account in the SentinelCrypt web app.
2. Open the Supabase **Table Editor** &rarr; `user_roles` table.
3. Change your user's role from `'user'` to `'admin'` (or run `UPDATE public.user_roles SET role = 'admin' WHERE user_id = 'YOUR_USER_ID';` in the SQL Editor).

---

## Step 6: Start or Restart the Development Server

Restart the development server to load the updated `.env` configuration:

```bash
npm run dev
```

---

## Verification Checklist

- [ ] Web app loads at `http://localhost:5173` without missing-environment errors.
- [ ] Sign up / Login works with automatic profile initialization (Trust score = 100, Status = `TRUSTED`).
- [ ] User public/wrapped RSA keys generate automatically on first setup.
- [ ] Secure File Transfer encrypts locally (AES-256-GCM + RSA-OAEP-2048) and uploads to `encrypted-payloads`.
- [ ] Receiver download verifies SHA-256 integrity and records telemetry.
- [ ] Security Lab (`/security-lab`) controlled tests trigger real threat logging and trust score deductions.
- [ ] Security Digital Twin (`/digital-twin`) displays live SOC metrics, Leaflet radar map, and user topology nodes.
