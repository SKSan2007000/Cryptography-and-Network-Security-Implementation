import { beforeEach, describe, expect, it } from "vitest";

import { evaluateDownloadGate } from "./download-gate.server";
import type { Admin } from "./security.server";

/* ------------------------------------------------------------------ */
/* Minimal in-memory stand-in for the privileged Supabase client.      */
/* It supports exactly the query shapes used by the download gate.     */
/* ------------------------------------------------------------------ */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Row = any;
interface Db {
  transfers: Row[];
  profiles: Row[];
  transfer_keys: Row[];
  app_sessions: Row[];
  notifications: Row[];
  audit_logs: Row[];
  threat_incidents: Row[];
  security_events: Row[];
  trust_events: Row[];
  devices: Row[];
  [key: string]: Row[] | undefined;
}

function matches(row: Row, filters: { op: string; col: string; value: unknown }[]): boolean {
  return filters.every((f) => {
    const v = row[f.col];
    switch (f.op) {
      case "eq":
        return v === f.value;
      case "gt":
        return String(v) > String(f.value);
      case "gte":
        return String(v) >= String(f.value);
      case "lt":
        return String(v) < String(f.value);
      default:
        return true;
    }
  });
}

function makeAdmin(db: Db) {
  const table = (name: string) => (db[name] ??= []);

  const builder = (name: string, mode: "select" | "update" | "insert", payload?: Row) => {
    const filters: { op: string; col: string; value: unknown }[] = [];
    const api: Record<string, unknown> = {};
    const run = () => {
      const rows = table(name).filter((r) => matches(r, filters));
      if (mode === "update") {
        rows.forEach((r) => Object.assign(r, payload));
        return { data: rows, error: null, count: rows.length };
      }
      return { data: rows, error: null, count: rows.length };
    };
    for (const op of ["eq", "gt", "gte", "lt", "neq"]) {
      api[op] = (col: string, value: unknown) => {
        filters.push({ op, col, value });
        return api;
      };
    }
    api["order"] = () => api;
    api["limit"] = () => api;
    api["select"] = () => api;
    api["maybeSingle"] = async () => {
      const { data } = run();
      return { data: data[0] ?? null, error: null };
    };
    api["single"] = async () => {
      const { data } = run();
      return { data: data[0] ?? null, error: null };
    };
    api["then"] = (resolve: (v: unknown) => unknown) => resolve(run());
    return api;
  };

  const admin = {
    from(name: string) {
      return {
        select: () => builder(name, "select"),
        update: (payload: Row) => builder(name, "update", payload),
        insert: (payload: Row | Row[]) => {
          const rows = Array.isArray(payload) ? payload : [payload];
          const inserted: Row[] = [];
          rows.forEach((r) => {
            const item = { id: crypto.randomUUID(), created_at: new Date().toISOString(), ...r };
            table(name).push(item);
            inserted.push(item);
          });
          const api: Record<string, unknown> = {
            data: inserted,
            error: null,
            select: () => api,
            maybeSingle: async () => ({ data: inserted[0] ?? null, error: null }),
            single: async () => ({ data: inserted[0] ?? null, error: null }),
            then: (resolve: (v: unknown) => unknown) => resolve({ data: inserted, error: null }),
          };
          return api;
        },
      };
    },
    storage: {
      from: () => ({
        createSignedUrl: async () => ({
          data: { signedUrl: "https://example.test/x" },
          error: null,
        }),
      }),
    },
  };
  return admin as unknown as Admin;
}

/** SHA-256("valid-token") — the gate compares hashes, never raw tokens. */
async function hash(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const RECIPIENT = "11111111-1111-1111-1111-111111111111";
const SENDER = "22222222-2222-2222-2222-222222222222";
const OUTSIDER = "33333333-3333-3333-3333-333333333333";
const TRANSFER = "44444444-4444-4444-4444-444444444444";
const TOKEN = "valid-token";

let db: Db;

async function baseDb(overrides: Row = {}): Promise<Db> {
  return {
    transfers: [
      {
        id: TRANSFER,
        sender_id: SENDER,
        recipient_id: RECIPIENT,
        status: "ENCRYPTED",
        storage_path: "path.enc",
        iv: "iv",
        original_sha256: "a".repeat(64),
        ciphertext_sha256: "b".repeat(64),
        token_hash: await hash(TOKEN),
        token_used_at: null,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        max_downloads: 1,
        download_count: 0,
        failed_attempts: 0,
        metrics: {},
        ...overrides,
      },
    ],
    profiles: [
      { id: RECIPIENT, trust_score: 100, trust_status: "TRUSTED" },
      { id: SENDER, trust_score: 100, trust_status: "TRUSTED" },
      { id: OUTSIDER, trust_score: 100, trust_status: "TRUSTED" },
    ],
    app_sessions: [
      {
        id: "session-1",
        user_id: RECIPIENT,
        revoked: false,
        ip_address: "127.0.0.1",
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        created_at: new Date().toISOString(),
      },
      {
        id: "session-2",
        user_id: OUTSIDER,
        revoked: false,
        ip_address: "127.0.0.1",
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        created_at: new Date().toISOString(),
      },
    ],
    transfer_keys: [{ transfer_id: TRANSFER, wrapped_key: "wrapped" }],
    audit_logs: [],
    notifications: [],
    threat_incidents: [],
    security_events: [],
    trust_events: [],
    devices: [],
  };
}

function gate(admin: Admin, over: Partial<Parameters<typeof evaluateDownloadGate>[1]> = {}) {
  return evaluateDownloadGate(admin, {
    transferId: TRANSFER,
    actorId: RECIPIENT,
    token: TOKEN,
    ip: "127.0.0.1",
    deviceFingerprint: "device-1",
    issueSignedUrl: false,
    ...over,
  });
}

describe("download gate", () => {
  beforeEach(async () => {
    db = await baseDb();
  });

  it("allows the designated recipient with a valid token", async () => {
    const admin = makeAdmin(db);
    const result = await gate(admin);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.wrappedKey).toBe("wrapped");
    expect(db.transfers[0]?.status).toBe("VERIFYING");
    expect(db.transfers[0]?.download_count).toBe(1);
    expect(db.transfers[0]?.token_used_at).toBeTruthy();
  });

  it("records consented receiver coordinates when provided", async () => {
    const admin = makeAdmin(db);
    const result = await gate(admin, {
      receiverLatitude: 37.7749,
      receiverLongitude: -122.4194,
    });
    expect(result.ok).toBe(true);
    expect(db.transfers[0]?.receiver_latitude).toBe(37.7749);
    expect(db.transfers[0]?.receiver_longitude).toBe(-122.4194);
  });

  it("blocks receiver when trust score is below 60", async () => {
    const lowTrustDb = await baseDb();
    const recipientProfile = lowTrustDb.profiles.find((p) => p.id === RECIPIENT);
    if (recipientProfile) {
      recipientProfile.trust_score = 45;
      recipientProfile.trust_status = "HIGH RISK";
    }
    const admin = makeAdmin(lowTrustDb);
    const result = await gate(admin);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("TRUST_EVALUATION");
    expect(result.threat?.type).toBe("UNAUTHORIZED_RECEIVER");
  });

  it("blocks an invalid token and records a threat", async () => {
    const admin = makeAdmin(db);
    const result = await gate(admin, { token: "bogus-token" });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("TOKEN");
    expect(result.threat?.type).toBe("INVALID_TOKEN");
  });

  it("blocks an unauthorized receiver even with a valid token", async () => {
    const admin = makeAdmin(db);
    const result = await gate(admin, { actorId: OUTSIDER });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("AUTHORIZATION");
    expect(result.threat?.type).toBe("UNAUTHORIZED_RECEIVER");
  });

  it("blocks replay of a consumed one-time token", async () => {
    db = await baseDb({ token_used_at: new Date().toISOString() });
    const admin = makeAdmin(db);
    const result = await gate(admin);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("REPLAY");
    expect(result.threat?.type).toBe("TOKEN_REPLAY");
  });

  it("blocks an expired transfer", async () => {
    db = await baseDb({ expires_at: new Date(Date.now() - 1000).toISOString() });
    const admin = makeAdmin(db);
    const result = await gate(admin);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("EXPIRY");
  });

  it("blocks once the download limit is reached", async () => {
    db = await baseDb({ download_count: 1, max_downloads: 1 });
    const admin = makeAdmin(db);
    const result = await gate(admin);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("DOWNLOAD_LIMIT");
  });

  it("blocks when no active session exists", async () => {
    db.app_sessions = [];
    const admin = makeAdmin(db);
    const result = await gate(admin);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.stage).toBe("SESSION");
    expect(result.threat?.type).toBe("EXPIRED_SESSION");
  });

  it("notifies legitimate users and writes an audit trail when blocking", async () => {
    const admin = makeAdmin(db);
    await gate(admin, { token: "tampered-token" });
    expect(db.notifications.length).toBeGreaterThanOrEqual(1);
    expect(db.audit_logs.length).toBeGreaterThanOrEqual(1);
  });
});
