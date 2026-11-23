/**
 * Server-Side Authentication Engine for Persistent Local Adapter
 *
 * Implements real account registration and login:
 * - Password hashing with PBKDF2 (salt + 100,000 iterations + SHA-512)
 * - Timing-safe password verification
 * - Persistent session tracking in SQLite `app_sessions`
 * - Profile and role management
 * - Plaintext passwords are NEVER stored in the database.
 */
import crypto from "node:crypto";
import { executeInsert, executeSelect, executeUpdate, getLocalDatabase } from "./db.server";

export type LocalUser = {
  id: string;
  email: string;
  user_metadata: {
    full_name?: string | null;
  };
  created_at: string;
};

export type LocalSession = {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at: number;
  user: LocalUser;
};

export type AuthResult = {
  user: LocalUser | null;
  session: LocalSession | null;
  error: { message: string } | null;
};

function hashPassword(password: string, salt: string): string {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
}

function verifyPassword(password: string, storedHash: string, salt: string): boolean {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, "sha512").toString("hex");
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash, "hex"));
}

export async function localSignUp(input: {
  email: string;
  password: string;
  fullName?: string | null | undefined;
}): Promise<AuthResult> {
  const email = input.email.trim().toLowerCase();
  if (!email || !input.password || input.password.length < 8) {
    return {
      user: null,
      session: null,
      error: { message: "Invalid email or password length (minimum 8 characters)." },
    };
  }

  // Check existing user
  const existing = executeSelect({
    table: "profiles",
    filters: [{ column: "email", op: "eq", value: email }],
  });

  if (existing.length > 0) {
    return { user: null, session: null, error: { message: "User already registered." } };
  }

  const userId = crypto.randomUUID();
  const salt = crypto.randomBytes(16).toString("hex");
  const passwordHash = hashPassword(input.password, salt);
  const nowIso = new Date().toISOString();

  // Create Profile
  executeInsert("profiles", {
    id: userId,
    email,
    full_name: input.fullName?.trim() ?? null,
    password_hash: passwordHash,
    password_salt: salt,
    trust_score: 85,
    trust_status: "NORMAL",
    status: "active",
    is_suspended: 0,
    created_at: nowIso,
    updated_at: nowIso,
  });

  // Assign role: if this is the first registered profile, assign admin, else user
  const allProfiles = executeSelect({ table: "profiles" });
  const role = allProfiles.length <= 1 ? "admin" : "user";
  executeInsert("user_roles", {
    id: crypto.randomUUID(),
    user_id: userId,
    role,
    created_at: nowIso,
  });

  // Create session
  const token = crypto.randomBytes(32).toString("hex");
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

  executeInsert("app_sessions", {
    id: crypto.randomUUID(),
    user_id: userId,
    token,
    token_hash: crypto.createHash("sha256").update(token).digest("hex"),
    device_fingerprint: "local-dev-browser",
    ip_address: "127.0.0.1",
    revoked: 0,
    expires_at: expiresAt,
    created_at: nowIso,
  });

  const user: LocalUser = {
    id: userId,
    email,
    user_metadata: { full_name: input.fullName?.trim() ?? null },
    created_at: nowIso,
  };

  const session: LocalSession = {
    access_token: token,
    token_type: "bearer",
    expires_in: 7 * 24 * 3600,
    expires_at: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    user,
  };

  return { user, session, error: null };
}

export async function localSignIn(input: { email: string; password: string }): Promise<AuthResult> {
  const email = input.email.trim().toLowerCase();
  const rows = executeSelect({
    table: "profiles",
    filters: [{ column: "email", op: "eq", value: email }],
  });

  if (rows.length === 0) {
    return { user: null, session: null, error: { message: "Invalid email or password." } };
  }

  const profile = rows[0]!;
  if (profile["is_suspended"]) {
    return {
      user: null,
      session: null,
      error: { message: "This account has been suspended for security policy violations." },
    };
  }

  const salt = profile["password_salt"] as string | undefined;
  const storedHash = profile["password_hash"] as string | undefined;

  if (!salt || !storedHash || !verifyPassword(input.password, storedHash, salt)) {
    return { user: null, session: null, error: { message: "Invalid email or password." } };
  }

  const userId = profile["id"] as string;
  const token = crypto.randomBytes(32).toString("hex");
  const nowIso = new Date().toISOString();
  const expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();

  executeInsert("app_sessions", {
    id: crypto.randomUUID(),
    user_id: userId,
    token,
    token_hash: crypto.createHash("sha256").update(token).digest("hex"),
    device_fingerprint: "local-dev-browser",
    ip_address: "127.0.0.1",
    revoked: 0,
    expires_at: expiresAt,
    created_at: nowIso,
  });

  const user: LocalUser = {
    id: userId,
    email: profile["email"] as string,
    user_metadata: { full_name: (profile["full_name"] as string | null) ?? null },
    created_at: profile["created_at"] as string,
  };

  const session: LocalSession = {
    access_token: token,
    token_type: "bearer",
    expires_in: 7 * 24 * 3600,
    expires_at: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
    user,
  };

  return { user, session, error: null };
}

export function localGetUserFromToken(token: string): LocalUser | null {
  if (!token) return null;
  const nowIso = new Date().toISOString();

  const sessions = executeSelect({
    table: "app_sessions",
    filters: [
      { column: "token", op: "eq", value: token },
      { column: "revoked", op: "eq", value: 0 },
      { column: "expires_at", op: "gt", value: nowIso },
    ],
  });

  if (sessions.length === 0) return null;
  const session = sessions[0]!;
  const userId = session["user_id"] as string;

  const profiles = executeSelect({
    table: "profiles",
    filters: [{ column: "id", op: "eq", value: userId }],
  });

  if (profiles.length === 0) return null;
  const profile = profiles[0]!;

  return {
    id: profile["id"] as string,
    email: profile["email"] as string,
    user_metadata: { full_name: (profile["full_name"] as string | null) ?? null },
    created_at: profile["created_at"] as string,
  };
}

export function localSignOut(token: string): { error: null } {
  if (token) {
    executeUpdate("app_sessions", { revoked: 1, revoked_reason: "USER_SIGNOUT" }, [
      { column: "token", op: "eq", value: token },
    ]);
  }
  return { error: null };
}
