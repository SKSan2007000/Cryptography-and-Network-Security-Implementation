/**
 * Persistent SQLite Database Engine for Local Development Adapter
 *
 * Stores all platform state persistently on disk in `./data/sentinelcrypt.db`.
 * No in-memory arrays. Retains state across restarts, server reloads and tests.
 */
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

let dbInstance: DatabaseSync | null = null;

function getDataDir(): string {
  const dir = path.resolve(process.cwd(), "data");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

export function getDatabasePath(): string {
  return path.join(getDataDir(), "sentinelcrypt.db");
}

export function getLocalDatabase(): DatabaseSync {
  if (dbInstance) return dbInstance;

  const dbPath = getDatabasePath();
  const db = new DatabaseSync(dbPath);

  // Enable WAL mode and foreign keys for durability and performance
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA foreign_keys = ON;");

  initSchema(db);
  dbInstance = db;
  return dbInstance;
}

function initSchema(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS profiles (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      full_name TEXT,
      organization TEXT,
      password_hash TEXT,
      password_salt TEXT,
      trust_score INTEGER DEFAULT 85 CHECK(trust_score >= 0 AND trust_score <= 100),
      trust_status TEXT DEFAULT 'NORMAL',
      trust_updated_at TEXT DEFAULT (datetime('now')),
      status TEXT DEFAULT 'active',
      is_suspended INTEGER DEFAULT 0,
      latitude REAL,
      longitude REAL,
      location_timestamp TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      updated_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS user_roles (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      role TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(user_id, role)
    );

    CREATE TABLE IF NOT EXISTS user_keys (
      id TEXT PRIMARY KEY,
      user_id TEXT UNIQUE NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      public_key_jwk TEXT NOT NULL,
      wrapped_private_key TEXT NOT NULL,
      kdf_salt TEXT NOT NULL,
      wrap_iv TEXT NOT NULL,
      algorithm TEXT DEFAULT 'RSA-OAEP-2048-SHA256',
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      fingerprint TEXT NOT NULL,
      device_name TEXT,
      user_agent TEXT,
      trusted INTEGER DEFAULT 1,
      last_seen TEXT DEFAULT (datetime('now')),
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS app_sessions (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      token_hash TEXT,
      device_fingerprint TEXT,
      ip_address TEXT,
      user_agent TEXT,
      revoked INTEGER DEFAULT 0,
      revoked_reason TEXT,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id TEXT PRIMARY KEY,
      sender_id TEXT NOT NULL REFERENCES profiles(id),
      recipient_id TEXT NOT NULL REFERENCES profiles(id),
      status TEXT NOT NULL,
      security_level TEXT DEFAULT 'standard',
      token_hash TEXT NOT NULL,
      storage_path TEXT,
      iv TEXT NOT NULL,
      original_sha256 TEXT NOT NULL,
      ciphertext_sha256 TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      max_downloads INTEGER DEFAULT 1,
      download_count INTEGER DEFAULT 0,
      failed_attempts INTEGER DEFAULT 0,
      is_tampered INTEGER DEFAULT 0,
      token_used_at TEXT,
      sender_token_wrapped TEXT,
      terminated_reason TEXT,
      sender_latitude REAL,
      sender_longitude REAL,
      sender_location_timestamp TEXT,
      receiver_latitude REAL,
      receiver_longitude REAL,
      receiver_location_timestamp TEXT,
      metrics TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transfer_keys (
      id TEXT PRIMARY KEY,
      transfer_id TEXT UNIQUE NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
      wrapped_key TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS file_metadata (
      id TEXT PRIMARY KEY,
      transfer_id TEXT NOT NULL REFERENCES transfers(id) ON DELETE CASCADE,
      original_name TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      mime_type TEXT NOT NULL,
      extension TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES profiles(id),
      transfer_id TEXT REFERENCES transfers(id),
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info',
      ip_address TEXT,
      trust_delta INTEGER DEFAULT 0,
      simulated INTEGER DEFAULT 0,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS threat_incidents (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES profiles(id),
      transfer_id TEXT REFERENCES transfers(id),
      threat_type TEXT NOT NULL,
      severity TEXT NOT NULL,
      action_taken TEXT NOT NULL,
      trust_delta INTEGER DEFAULT 0,
      blocked INTEGER DEFAULT 1,
      simulated INTEGER DEFAULT 0,
      details TEXT,
      resolved INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS trust_events (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES profiles(id),
      security_event_id TEXT REFERENCES security_events(id),
      previous_score INTEGER NOT NULL,
      new_score INTEGER NOT NULL,
      delta INTEGER NOT NULL,
      reason TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES profiles(id),
      transfer_id TEXT REFERENCES transfers(id),
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      severity TEXT DEFAULT 'info',
      read INTEGER DEFAULT 0,
      is_read INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      user_id TEXT REFERENCES profiles(id),
      transfer_id TEXT REFERENCES transfers(id),
      event TEXT NOT NULL,
      action TEXT,
      severity TEXT DEFAULT 'info',
      ip_address TEXT,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- Indexes for fast query resolution
    CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_id);
    CREATE INDEX IF NOT EXISTS idx_transfers_recipient ON transfers(recipient_id);
    CREATE INDEX IF NOT EXISTS idx_file_metadata_transfer ON file_metadata(transfer_id);
    CREATE INDEX IF NOT EXISTS idx_transfer_keys_transfer ON transfer_keys(transfer_id);
    CREATE INDEX IF NOT EXISTS idx_app_sessions_user ON app_sessions(user_id);
    CREATE INDEX IF NOT EXISTS idx_app_sessions_token ON app_sessions(token);
    CREATE INDEX IF NOT EXISTS idx_security_events_transfer ON security_events(transfer_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_transfer ON audit_logs(transfer_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_trust_events_user ON trust_events(user_id);
    CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
  `);

  try {
    db.exec("ALTER TABLE profiles ADD COLUMN trust_updated_at TEXT DEFAULT NULL;");
  } catch {
    /* Column already exists */
  }
}

export type QueryFilter = {
  column: string;
  op: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "is";
  value: unknown;
};

export type QueryOrder = {
  column: string;
  ascending?: boolean | undefined;
};

export type QueryParams = {
  table: string;
  select?: string | undefined;
  filters?: QueryFilter[] | undefined;
  order?: QueryOrder[] | undefined;
  limit?: number | undefined;
  offset?: number | undefined;
};

/**
 * Execute PostgREST-like query against the persistent SQLite database
 */
export function executeSelect(params: QueryParams): Record<string, unknown>[] {
  const db = getLocalDatabase();
  const { table, filters = [], order = [], limit, offset } = params;

  let sql = `SELECT * FROM ${table}`;
  const whereClauses: string[] = [];
  const bindings: unknown[] = [];

  for (const f of filters) {
    if (f.op === "is") {
      whereClauses.push(`${f.column} IS ${f.value === null ? "NULL" : String(f.value)}`);
    } else {
      const opMap: Record<string, string> = {
        eq: "=",
        neq: "!=",
        gt: ">",
        gte: ">=",
        lt: "<",
        lte: "<=",
      };
      const sqlOp = opMap[f.op] ?? "=";
      whereClauses.push(`${f.column} ${sqlOp} ?`);
      // SQLite stores booleans as 0 or 1
      let val = f.value;
      if (typeof val === "boolean") val = val ? 1 : 0;
      bindings.push(val);
    }
  }

  if (whereClauses.length > 0) {
    sql += ` WHERE ${whereClauses.join(" AND ")}`;
  }

  if (order.length > 0) {
    const orderParts = order.map((o) => `${o.column} ${o.ascending === false ? "DESC" : "ASC"}`);
    sql += ` ORDER BY ${orderParts.join(", ")}`;
  }

  if (typeof limit === "number") {
    sql += ` LIMIT ${limit}`;
    if (typeof offset === "number") {
      sql += ` OFFSET ${offset}`;
    }
  }

  const stmt = db.prepare(sql);
  const rows = stmt.all(
    ...(bindings as (string | number | bigint | null | Uint8Array)[]),
  ) as Record<string, unknown>[];

  // Post-process row data: deserialize JSON columns and handle joins
  const processedRows = rows.map((r) => postProcessRow(table, r));

  // If select includes file_metadata relationship on transfers, join it
  if (table === "transfers" && (params.select?.includes("file_metadata") ?? true)) {
    const metaStmt = db.prepare(
      "SELECT original_name, size_bytes, mime_type, extension FROM file_metadata WHERE transfer_id = ?",
    );
    for (const row of processedRows) {
      const transferId = row["id"] as string;
      const metaRows = metaStmt.all(transferId) as Record<string, unknown>[];
      row["file_metadata"] = metaRows;
    }
  }

  return processedRows;
}

function postProcessRow(table: string, row: Record<string, unknown>): Record<string, unknown> {
  const result = { ...row };

  // Parse JSON fields
  for (const key of ["details", "metadata", "metrics"]) {
    if (typeof result[key] === "string") {
      try {
        result[key] = JSON.parse(result[key] as string);
      } catch {
        // Keep as string
      }
    }
  }

  // Parse public_key_jwk in user_keys
  if (table === "user_keys" && typeof result["public_key_jwk"] === "string") {
    try {
      result["public_key_jwk"] = JSON.parse(result["public_key_jwk"] as string);
    } catch {
      // Keep as string
    }
  }

  // Convert SQLite integers 0/1 to boolean where appropriate
  for (const key of [
    "revoked",
    "trusted",
    "is_suspended",
    "is_tampered",
    "is_read",
    "blocked",
    "simulated",
    "resolved",
  ]) {
    if (key in result) result[key] = Boolean(result[key]);
  }

  return result;
}

export function executeInsert(
  table: string,
  rows: Record<string, unknown> | Record<string, unknown>[],
): Record<string, unknown>[] {
  const db = getLocalDatabase();
  const list = Array.isArray(rows) ? rows : [rows];
  const inserted: Record<string, unknown>[] = [];

  for (const item of list) {
    const data = { ...item };
    if (!data["id"]) {
      data["id"] = crypto.randomUUID();
    }

    const columns = Object.keys(data);
    const placeholders = columns.map(() => "?").join(", ");
    const values = columns.map((col) => {
      const val = data[col];
      if (val === undefined) return null;
      if (typeof val === "boolean") return val ? 1 : 0;
      if (
        typeof val === "object" &&
        val !== null &&
        !(val instanceof Uint8Array) &&
        !(val instanceof Buffer)
      ) {
        return JSON.stringify(val);
      }
      return val;
    });

    const sql = `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})`;
    db.prepare(sql).run(...(values as (string | number | bigint | null | Uint8Array)[]));

    const selected = db
      .prepare(`SELECT * FROM ${table} WHERE id = ?`)
      .get(data["id"] as string) as Record<string, unknown>;
    inserted.push(postProcessRow(table, selected));
  }

  return inserted;
}

export function executeUpdate(
  table: string,
  payload: Record<string, unknown>,
  filters: QueryFilter[],
): Record<string, unknown>[] {
  const db = getLocalDatabase();
  const data = { ...payload };

  const setClauses: string[] = [];
  const bindings: unknown[] = [];

  for (const [col, rawVal] of Object.entries(data)) {
    let val = rawVal;
    if (val === undefined) val = null;
    if (typeof val === "boolean") val = val ? 1 : 0;
    if (
      typeof val === "object" &&
      val !== null &&
      !(val instanceof Uint8Array) &&
      !(val instanceof Buffer)
    ) {
      val = JSON.stringify(val);
    }
    setClauses.push(`${col} = ?`);
    bindings.push(val);
  }

  const whereClauses: string[] = [];
  for (const f of filters) {
    whereClauses.push(`${f.column} = ?`);
    let val = f.value;
    if (val === undefined) val = null;
    if (typeof val === "boolean") val = val ? 1 : 0;
    bindings.push(val);
  }

  let sql = `UPDATE ${table} SET ${setClauses.join(", ")}`;
  if (whereClauses.length > 0) {
    sql += ` WHERE ${whereClauses.join(" AND ")}`;
  }

  db.prepare(sql).run(...(bindings as (string | number | bigint | null | Uint8Array)[]));

  // Return updated rows
  return executeSelect({ table, filters });
}

export function executeUpsert(
  table: string,
  payload: Record<string, unknown>,
  conflictColumn: string,
): Record<string, unknown> {
  const db = getLocalDatabase();
  const existing = executeSelect({
    table,
    filters: [{ column: conflictColumn, op: "eq", value: payload[conflictColumn] }],
  });

  if (existing.length > 0) {
    const updated = executeUpdate(table, payload, [
      { column: conflictColumn, op: "eq", value: payload[conflictColumn] },
    ]);
    return updated[0] ?? payload;
  } else {
    const inserted = executeInsert(table, payload);
    return inserted[0] ?? payload;
  }
}

export function executeDelete(table: string, filters: QueryFilter[]) {
  const db = getLocalDatabase();
  const whereClauses: string[] = [];
  const bindings: unknown[] = [];

  for (const f of filters) {
    whereClauses.push(`${f.column} = ?`);
    bindings.push(f.value);
  }

  let sql = `DELETE FROM ${table}`;
  if (whereClauses.length > 0) {
    sql += ` WHERE ${whereClauses.join(" AND ")}`;
  }

  db.prepare(sql).run(...(bindings as (string | number | bigint | null | Uint8Array)[]));
}
