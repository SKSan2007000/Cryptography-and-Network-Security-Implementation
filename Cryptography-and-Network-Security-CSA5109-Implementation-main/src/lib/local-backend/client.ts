/**
 * Browser Client for Persistent Local Backend Adapter
 *
 * Implements the exact same interface as the Supabase browser client,
 * delegating to TanStack Start server functions and persistent SQLite storage.
 * Maintains authenticated session in localStorage.
 */
import type { Session, User } from "@supabase/supabase-js";
import {
  localBackendAuthFn,
  localBackendDbFn,
  localStorageUploadFn,
  localBackendRpcFn,
} from "./server-functions";

const STORAGE_SESSION_KEY = "sentinelcrypt_local_auth_session";

type AuthListener = (
  event: "SIGNED_IN" | "SIGNED_OUT" | "TOKEN_REFRESHED",
  session: Session | null,
) => void;
const authListeners = new Set<AuthListener>();

function notifyAuthChange(
  event: "SIGNED_IN" | "SIGNED_OUT" | "TOKEN_REFRESHED",
  session: Session | null,
) {
  for (const listener of authListeners) {
    try {
      listener(event, session);
    } catch (err) {
      console.error("[LocalAuth] Error in auth state change listener:", err);
    }
  }
}

function getStoredSession(): Session | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(STORAGE_SESSION_KEY);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Session;
    if (parsed.expires_at && parsed.expires_at < Math.floor(Date.now() / 1000)) {
      localStorage.removeItem(STORAGE_SESSION_KEY);
      return null;
    }
    return parsed;
  } catch {
    localStorage.removeItem(STORAGE_SESSION_KEY);
    return null;
  }
}

function setStoredSession(session: Session | null) {
  if (typeof window === "undefined") return;
  if (!session) {
    localStorage.removeItem(STORAGE_SESSION_KEY);
  } else {
    localStorage.setItem(STORAGE_SESSION_KEY, JSON.stringify(session));
  }
}

export function createLocalClient() {
  return {
    auth: {
      signUp: async ({
        email,
        password,
        options,
      }: {
        email: string;
        password: string;
        options?: { data?: { full_name?: string } };
      }) => {
        const res = (await localBackendAuthFn({
          data: {
            action: "signUp",
            email,
            password,
            fullName: options?.data?.full_name ?? null,
          },
        })) as unknown as {
          user: User | null;
          session: Session | null;
          error: { message: string } | null;
        };

        if (res.error) {
          return { data: { user: null, session: null }, error: res.error };
        }

        const session = res.session;
        const user = res.user;

        setStoredSession(session);
        notifyAuthChange("SIGNED_IN", session);
        return { data: { user, session }, error: null };
      },

      signInWithPassword: async ({ email, password }: { email: string; password: string }) => {
        const res = (await localBackendAuthFn({
          data: {
            action: "signIn",
            email,
            password,
          },
        })) as unknown as {
          user: User | null;
          session: Session | null;
          error: { message: string } | null;
        };

        if (res.error) {
          return { data: { user: null, session: null }, error: res.error };
        }

        const session = res.session;
        const user = res.user;

        setStoredSession(session);
        notifyAuthChange("SIGNED_IN", session);
        return { data: { user, session }, error: null };
      },

      signOut: async () => {
        const session = getStoredSession();
        if (session) {
          await localBackendAuthFn({
            data: {
              action: "signOut",
              token: session.access_token,
            },
          }).catch(() => null);
        }

        setStoredSession(null);
        notifyAuthChange("SIGNED_OUT", null);
        return { error: null };
      },

      getSession: async () => {
        const session = getStoredSession();
        return { data: { session }, error: null };
      },

      getUser: async () => {
        const session = getStoredSession();
        if (!session?.access_token) return { data: { user: null }, error: null };

        const res = (await localBackendAuthFn({
          data: {
            action: "getUser",
            token: session.access_token,
          },
        })) as unknown as { user: User | null; error: { message: string } | null };

        if (res.user) {
          return { data: { user: res.user }, error: null };
        } else {
          setStoredSession(null);
          return { data: { user: null }, error: null };
        }
      },

      onAuthStateChange: (callback: AuthListener) => {
        authListeners.add(callback);
        // Immediately fire with current session
        const current = getStoredSession();
        setTimeout(() => callback(current ? "SIGNED_IN" : "SIGNED_OUT", current), 0);

        return {
          data: {
            subscription: {
              unsubscribe: () => {
                authListeners.delete(callback);
              },
            },
          },
        };
      },

      resetPasswordForEmail: async (_email: string) => {
        return { data: {}, error: null };
      },
    },

    from: (table: string) => {
      let selectCols: string | undefined = undefined;
      const filters: {
        column: string;
        op: "eq" | "neq" | "gt" | "gte" | "lt" | "lte" | "is";
        value: string | number | boolean | null;
      }[] = [];
      const orders: { column: string; ascending?: boolean }[] = [];
      let limitCount: number | undefined = undefined;

      const execute = async () => {
        const session = getStoredSession();
        const res = await localBackendDbFn({
          data: {
            operation: "select",
            table,
            select: selectCols,
            filters,
            order: orders,
            limit: limitCount,
            token: session?.access_token,
          },
        });
        return { data: res.data as unknown[], error: res.error, count: res.count };
      };

      const queryBuilder = {
        select: (cols = "*") => {
          selectCols = cols;
          return queryBuilder;
        },
        eq: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "eq", value });
          return queryBuilder;
        },
        neq: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "neq", value });
          return queryBuilder;
        },
        gt: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "gt", value });
          return queryBuilder;
        },
        gte: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "gte", value });
          return queryBuilder;
        },
        lt: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "lt", value });
          return queryBuilder;
        },
        lte: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "lte", value });
          return queryBuilder;
        },
        is: (column: string, value: string | number | boolean | null) => {
          filters.push({ column, op: "is", value });
          return queryBuilder;
        },
        order: (column: string, options?: { ascending?: boolean }) => {
          orders.push({ column, ascending: options?.ascending ?? true });
          return queryBuilder;
        },
        limit: (n: number) => {
          limitCount = n;
          return queryBuilder;
        },
        single: async () => {
          const res = await execute();
          return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
        },
        maybeSingle: async () => {
          const res = await execute();
          return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
        },
        then: (resolve: (v: unknown) => unknown) => {
          return execute().then(resolve);
        },
        insert: (payload: Record<string, unknown> | Record<string, unknown>[]) => {
          const runInsert = async () => {
            const session = getStoredSession();
            const res = await localBackendDbFn({
              data: {
                operation: "insert",
                table,
                payload,
                token: session?.access_token,
              },
            });
            return { data: res.data as unknown[], error: res.error };
          };

          const insertChain = {
            select: () => insertChain,
            single: async () => {
              const res = await runInsert();
              return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
            },
            maybeSingle: async () => {
              const res = await runInsert();
              return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
            },
            then: (resolve: (v: unknown) => unknown) => {
              return runInsert().then(resolve);
            },
          };
          return insertChain;
        },
        update: (payload: Record<string, unknown>) => {
          const updateBuilder = {
            eq: (column: string, value: string | number | boolean | null) => {
              filters.push({ column, op: "eq", value });
              return updateBuilder;
            },
            then: (resolve: (v: unknown) => unknown) => {
              const session = getStoredSession();
              return localBackendDbFn({
                data: {
                  operation: "update",
                  table,
                  payload,
                  filters,
                  token: session?.access_token,
                },
              }).then((res) => resolve({ data: res.data, error: res.error }));
            },
          };
          return updateBuilder;
        },
        upsert: (payload: Record<string, unknown>, options?: { onConflict?: string }) => {
          const runUpsert = async () => {
            const session = getStoredSession();
            const res = await localBackendDbFn({
              data: {
                operation: "upsert",
                table,
                payload,
                conflictColumn: options?.onConflict ?? "id",
                token: session?.access_token,
              },
            });
            return { data: res.data as unknown[], error: res.error };
          };

          const upsertChain = {
            select: () => upsertChain,
            single: async () => {
              const res = await runUpsert();
              return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
            },
            maybeSingle: async () => {
              const res = await runUpsert();
              return { data: (res.data?.[0] as unknown) ?? null, error: res.error };
            },
            then: (resolve: (v: unknown) => unknown) => {
              return runUpsert().then(resolve);
            },
          };
          return upsertChain;
        },
      };

      return queryBuilder;
    },

    storage: {
      from: (_bucket: string) => ({
        upload: async (
          storagePath: string,
          fileOrBlob: Blob | File | Uint8Array,
          _options?: { contentType?: string; upsert?: boolean },
        ) => {
          try {
            let buffer: Uint8Array;
            if (fileOrBlob instanceof Uint8Array) {
              buffer = fileOrBlob;
            } else {
              buffer = new Uint8Array(await fileOrBlob.arrayBuffer());
            }

            // Convert to base64
            let binary = "";
            const len = buffer.byteLength;
            for (let i = 0; i < len; i++) {
              binary += String.fromCharCode(buffer[i]!);
            }
            const payloadBase64 = btoa(binary);

            const session = getStoredSession();
            const res = await localStorageUploadFn({
              data: {
                storagePath,
                payloadBase64,
                token: session?.access_token,
              },
            });

            if (res.error) return { data: null, error: res.error };
            return { data: { path: storagePath }, error: null };
          } catch (err: unknown) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },
        createSignedUrl: async (storagePath: string, expiresIn = 300) => {
          // In local mode, returns direct download URL with token
          const url = `/api/local/storage/download?path=${encodeURIComponent(storagePath)}&expires=${Math.floor(Date.now() / 1000) + expiresIn}`;
          return { data: { signedUrl: url }, error: null };
        },
      }),
    },

    rpc: async (fn: string, args: Record<string, unknown> = {}) => {
      const session = getStoredSession();
      const res = await localBackendRpcFn({
        data: {
          fn,
          args,
          token: session?.access_token,
        },
      });
      return { data: res.data as unknown, error: res.error };
    },
  };
}
