/**
 * Backend Mode Configuration
 *
 * Detects whether the application has valid Supabase credentials available.
 * If credentials are missing or set to placeholders, seamlessly routes to
 * the persistent local SQLite and local encrypted storage backend.
 */

export type BackendMode = "supabase" | "local";

export function isSupabaseConfigured(): boolean {
  let url: string | undefined;
  let key: string | undefined;

  if (typeof process !== "undefined" && process.env) {
    url = process.env["SUPABASE_URL"] || process.env["VITE_SUPABASE_URL"];
    key =
      process.env["SUPABASE_PUBLISHABLE_KEY"] ||
      process.env["VITE_SUPABASE_PUBLISHABLE_KEY"] ||
      process.env["SUPABASE_ANON_KEY"];
  }

  if ((!url || !key) && typeof import.meta !== "undefined" && import.meta.env) {
    url = url || import.meta.env["VITE_SUPABASE_URL"] || import.meta.env["SUPABASE_URL"];
    key =
      key ||
      import.meta.env["VITE_SUPABASE_PUBLISHABLE_KEY"] ||
      import.meta.env["SUPABASE_PUBLISHABLE_KEY"] ||
      import.meta.env["VITE_SUPABASE_ANON_KEY"];
  }

  if (!url || !key) return false;

  const urlLower = url.toLowerCase().trim();
  const keyLower = key.toLowerCase().trim();

  if (
    urlLower.includes("placeholder") ||
    keyLower.includes("placeholder") ||
    urlLower.includes("your-project") ||
    urlLower.includes("example.com") ||
    keyLower === ""
  ) {
    return false;
  }

  return true;
}

export function getBackendMode(): BackendMode {
  return isSupabaseConfigured() ? "supabase" : "local";
}
