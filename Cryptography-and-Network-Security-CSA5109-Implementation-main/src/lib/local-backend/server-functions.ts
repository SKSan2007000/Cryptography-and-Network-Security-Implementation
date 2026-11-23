/**
 * TanStack Start Server Functions for Local Backend Adapter
 *
 * Exposes type-safe server endpoints for local authentication, SQLite queries,
 * encrypted payload upload, and RPC functions.
 */
import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import {
  executeDelete,
  executeInsert,
  executeSelect,
  executeUpdate,
  executeUpsert,
} from "./db.server";
import { localGetUserFromToken, localSignIn, localSignOut, localSignUp } from "./auth.server";
import { saveEncryptedPayload } from "./storage.server";

const authInputSchema = z.object({
  action: z.enum(["signUp", "signIn", "signOut", "getUser"]),
  email: z.string().optional(),
  password: z.string().optional(),
  fullName: z.string().nullable().optional(),
  token: z.string().optional(),
});

export const localBackendAuthFn = createServerFn({ method: "POST" })
  .validator((d: unknown) => authInputSchema.parse(d))
  .handler(async ({ data }) => {
    if (data.action === "signUp") {
      return await localSignUp({
        email: data.email ?? "",
        password: data.password ?? "",
        fullName: data.fullName,
      });
    }
    if (data.action === "signIn") {
      return await localSignIn({
        email: data.email ?? "",
        password: data.password ?? "",
      });
    }
    if (data.action === "signOut") {
      return localSignOut(data.token ?? "");
    }
    if (data.action === "getUser") {
      const user = localGetUserFromToken(data.token ?? "");
      return { user, error: null };
    }
    return { user: null, session: null, error: { message: "Invalid auth action" } };
  });

const filterSchema = z.object({
  column: z.string(),
  op: z.enum(["eq", "neq", "gt", "gte", "lt", "lte", "is"]),
  value: z.union([z.string(), z.number(), z.boolean(), z.null()]),
});

const orderSchema = z.object({
  column: z.string(),
  ascending: z.boolean().optional(),
});

const dbQuerySchema = z.object({
  operation: z.enum(["select", "insert", "update", "upsert", "delete"]),
  table: z.string(),
  select: z.string().optional(),
  filters: z.array(filterSchema).optional(),
  order: z.array(orderSchema).optional(),
  limit: z.number().optional(),
  offset: z.number().optional(),
  payload: z.any().optional(),
  conflictColumn: z.string().optional(),
  token: z.string().optional(),
});

export const localBackendDbFn = createServerFn({ method: "POST" })
  .validator((d: unknown) => dbQuerySchema.parse(d))
  .handler(async ({ data }) => {
    const {
      operation,
      table,
      select,
      filters = [],
      order = [],
      limit,
      offset,
      payload,
      conflictColumn,
    } = data;

    if (operation === "select") {
      const rows = executeSelect({ table, select, filters, order, limit, offset });
      return { data: rows as never, error: null, count: rows.length };
    }

    if (operation === "insert") {
      const inserted = executeInsert(
        table,
        payload as Record<string, unknown> | Record<string, unknown>[],
      );
      return { data: inserted as never, error: null, count: inserted.length };
    }

    if (operation === "update") {
      const updated = executeUpdate(table, payload as Record<string, unknown>, filters);
      return { data: updated as never, error: null, count: updated.length };
    }

    if (operation === "upsert") {
      const upserted = executeUpsert(
        table,
        payload as Record<string, unknown>,
        conflictColumn ?? "id",
      );
      return { data: [upserted] as never, error: null, count: 1 };
    }

    if (operation === "delete") {
      executeDelete(table, filters);
      return { data: null as never, error: null };
    }

    return { data: null as never, error: { message: "Unknown operation" } };
  });

const uploadSchema = z.object({
  storagePath: z.string(),
  payloadBase64: z.string(),
  token: z.string().optional(),
});

export const localStorageUploadFn = createServerFn({ method: "POST" })
  .validator((d: unknown) => uploadSchema.parse(d))
  .handler(async ({ data }) => {
    try {
      const buffer = Buffer.from(data.payloadBase64, "base64");
      const res = saveEncryptedPayload(data.storagePath, buffer);
      return { data: res, error: null };
    } catch (err: unknown) {
      return { data: null, error: { message: (err as Error).message } };
    }
  });

const rpcSchema = z.object({
  fn: z.string(),
  args: z.record(z.any()).optional(),
  token: z.string().optional(),
});

export const localBackendRpcFn = createServerFn({ method: "POST" })
  .validator((d: unknown) => rpcSchema.parse(d))
  .handler(async ({ data }) => {
    const { fn, args = {} } = data;
    if (fn === "has_role") {
      const userId = (args["_user_id"] ?? args["user_id"]) as string;
      const role = (args["_role"] ?? args["role"]) as string;
      const roles = executeSelect({
        table: "user_roles",
        filters: [
          { column: "user_id", op: "eq", value: userId },
          { column: "role", op: "eq", value: role },
        ],
      });
      return { data: (roles.length > 0) as never, error: null };
    }
    if (fn === "get_public_key") {
      const userId = (args["_user_id"] ?? args["user_id"]) as string;
      const keys = executeSelect({
        table: "user_keys",
        filters: [{ column: "user_id", op: "eq", value: userId }],
      });
      if (keys.length === 0) return { data: null as never, error: null };
      return { data: keys[0]!["public_key_jwk"] as never, error: null };
    }
    return { data: null as never, error: null };
  });
