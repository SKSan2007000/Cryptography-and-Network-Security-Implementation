/**
 * Server-only client facade.
 * Connects directly to FastAPI & PostgreSQL via createFastApiClient.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";
import { createFastApiClient } from "./fastapi-adapter";

let cached: SupabaseClient<Database> | undefined;

export function resolveServerKeyName(): "FASTAPI_JWT_SECRET" {
  return "FASTAPI_JWT_SECRET";
}

export function createAdminClient(): SupabaseClient<Database> {
  if (cached) return cached;
  cached = createFastApiClient() as unknown as SupabaseClient<Database>;
  return cached;
}
