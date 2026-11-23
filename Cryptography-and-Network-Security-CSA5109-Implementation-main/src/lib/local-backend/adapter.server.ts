/**
 * Server-Side Admin Adapter for Local SQLite Backend
 *
 * Implements the exact same PostgREST / SupabaseClient interface used by
 * security.server.ts, download-gate.server.ts, and sentinel.functions.ts.
 */
import {
  executeDelete,
  executeInsert,
  executeSelect,
  executeUpdate,
  executeUpsert,
  type QueryFilter,
  type QueryOrder,
} from "./db.server";
import {
  createSignedDownloadUrl,
  readEncryptedPayload,
  saveEncryptedPayload,
} from "./storage.server";

export function createLocalAdminClient() {
  return {
    from: (table: string) => {
      let selectedCols: string | undefined = undefined;
      const filters: QueryFilter[] = [];
      const orders: QueryOrder[] = [];
      let limitCount: number | undefined = undefined;
      let countExact = false;

      const runSelect = () => {
        const rows = executeSelect({
          table,
          select: selectedCols,
          filters,
          order: orders,
          limit: limitCount,
        });

        return {
          data: rows,
          error: null,
          count: countExact ? rows.length : null,
        };
      };

      const builder = {
        select: (cols = "*", opts?: { count?: "exact"; head?: boolean }) => {
          selectedCols = cols;
          if (opts?.count === "exact") countExact = true;
          return builder;
        },
        eq: (column: string, value: unknown) => {
          filters.push({ column, op: "eq", value });
          return builder;
        },
        neq: (column: string, value: unknown) => {
          filters.push({ column, op: "neq", value });
          return builder;
        },
        gt: (column: string, value: unknown) => {
          filters.push({ column, op: "gt", value });
          return builder;
        },
        gte: (column: string, value: unknown) => {
          filters.push({ column, op: "gte", value });
          return builder;
        },
        lt: (column: string, value: unknown) => {
          filters.push({ column, op: "lt", value });
          return builder;
        },
        lte: (column: string, value: unknown) => {
          filters.push({ column, op: "lte", value });
          return builder;
        },
        is: (column: string, value: unknown) => {
          filters.push({ column, op: "is", value });
          return builder;
        },
        order: (column: string, options?: { ascending?: boolean }) => {
          orders.push({ column, ascending: options?.ascending ?? true });
          return builder;
        },
        limit: (n: number) => {
          limitCount = n;
          return builder;
        },
        single: async () => {
          const res = runSelect();
          return { data: res.data[0] ?? null, error: null };
        },
        maybeSingle: async () => {
          const res = runSelect();
          return { data: res.data[0] ?? null, error: null };
        },
        then: (resolve: (val: unknown) => unknown) => {
          return Promise.resolve(runSelect()).then(resolve);
        },
        insert: (payload: Record<string, unknown> | Record<string, unknown>[]) => {
          const inserted = executeInsert(table, payload);
          const api = {
            data: inserted,
            error: null,
            select: () => api,
            single: async () => ({ data: inserted[0] ?? null, error: null }),
            maybeSingle: async () => ({ data: inserted[0] ?? null, error: null }),
            then: (resolve: (v: unknown) => unknown) =>
              Promise.resolve({ data: inserted, error: null }).then(resolve),
          };
          return api;
        },
        update: (payload: Record<string, unknown>) => {
          const updateBuilder = {
            eq: (column: string, value: unknown) => {
              filters.push({ column, op: "eq", value });
              return updateBuilder;
            },
            then: (resolve: (v: unknown) => unknown) => {
              const updated = executeUpdate(table, payload, filters);
              return Promise.resolve({ data: updated, error: null }).then(resolve);
            },
          };
          return updateBuilder;
        },
        upsert: (payload: Record<string, unknown>, options?: { onConflict?: string }) => {
          const conflictCol = options?.onConflict ?? "id";
          const upserted = executeUpsert(table, payload, conflictCol);
          const api = {
            data: upserted,
            error: null,
            select: () => api,
            single: async () => ({ data: upserted, error: null }),
            maybeSingle: async () => ({ data: upserted, error: null }),
            then: (resolve: (v: unknown) => unknown) =>
              Promise.resolve({ data: upserted, error: null }).then(resolve),
          };
          return api;
        },
        delete: () => {
          const delBuilder = {
            eq: (column: string, value: unknown) => {
              filters.push({ column, op: "eq", value });
              return delBuilder;
            },
            then: (resolve: (v: unknown) => unknown) => {
              executeDelete(table, filters);
              return Promise.resolve({ data: null, error: null }).then(resolve);
            },
          };
          return delBuilder;
        },
      };

      return builder;
    },
    storage: {
      from: (_bucket: string) => ({
        upload: async (storagePath: string, fileData: Buffer | Uint8Array) => {
          try {
            saveEncryptedPayload(storagePath, fileData);
            return { data: { path: storagePath }, error: null };
          } catch (err: unknown) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },
        createSignedUrl: async (storagePath: string, expiresInSeconds = 60) => {
          try {
            const { signedUrl } = createSignedDownloadUrl(storagePath, expiresInSeconds);
            return { data: { signedUrl }, error: null };
          } catch (err: unknown) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },
        download: async (storagePath: string) => {
          try {
            const buffer = readEncryptedPayload(storagePath);
            return { data: new Blob([new Uint8Array(buffer)]), error: null };
          } catch (err: unknown) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },
      }),
    },
    rpc: async (fn: string, args: Record<string, unknown> = {}) => {
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
        return { data: roles.length > 0, error: null };
      }
      if (fn === "get_public_key") {
        const userId = (args["_user_id"] ?? args["user_id"]) as string;
        const keys = executeSelect({
          table: "user_keys",
          filters: [{ column: "user_id", op: "eq", value: userId }],
        });
        if (keys.length === 0) return { data: null, error: null };
        return { data: keys[0]!["public_key_jwk"], error: null };
      }
      return { data: null, error: null };
    },
  };
}
