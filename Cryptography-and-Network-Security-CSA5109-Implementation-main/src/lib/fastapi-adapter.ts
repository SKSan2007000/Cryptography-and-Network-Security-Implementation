/**
 * FastAPI Client Adapter for SentinelCrypt
 *
 * Exposes the standard client contract expected by existing UI components,
 * routing all database, authentication, storage, and RPC operations directly
 * to the Python FastAPI backend connected to PostgreSQL.
 */

import { apiClient, type ApiUser, type ApiTransfer } from "./api-client";
import type { Session, User } from "@supabase/supabase-js";

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
      console.error("[FastAPIAuth] Auth change listener error:", err);
    }
  }
}

function userToSupabaseUser(apiUser: ApiUser): User {
  return {
    id: apiUser.id,
    app_metadata: { provider: "email", providers: ["email"], roles: apiUser.roles },
    user_metadata: {
      full_name: apiUser.profile?.full_name ?? apiUser.email.split("@")[0],
      organization: apiUser.profile?.organization ?? "Independent",
    },
    aud: "authenticated",
    email: apiUser.email,
    created_at: new Date().toISOString(),
    role: "authenticated",
    updated_at: new Date().toISOString(),
  } as unknown as User;
}

function buildSession(apiUser: ApiUser, token: string): Session {
  return {
    access_token: token,
    token_type: "bearer",
    expires_in: 604800,
    expires_at: Math.floor(Date.now() / 1000) + 604800,
    refresh_token: token,
    user: userToSupabaseUser(apiUser),
  };
}

export function createFastApiClient() {
  return {
    auth: {
      signUp: async ({
        email,
        password,
        options,
      }: {
        email: string;
        password: string;
        options?: { data?: { full_name?: string; organization?: string } };
      }) => {
        try {
          const res = await apiClient.register({
            email,
            password,
            full_name: options?.data?.full_name ?? null,
            organization: options?.data?.organization ?? null,
          });
          const session = buildSession(res.user, res.access_token);
          notifyAuthChange("SIGNED_IN", session);
          return { data: { user: session.user, session }, error: null };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { message: (err as Error).message },
          };
        }
      },

      signInWithPassword: async ({ email, password }: { email: string; password: string }) => {
        try {
          const res = await apiClient.login({ email, password });
          const session = buildSession(res.user, res.access_token);
          notifyAuthChange("SIGNED_IN", session);
          return { data: { user: session.user, session }, error: null };
        } catch (err) {
          return {
            data: { user: null, session: null },
            error: { message: (err as Error).message },
          };
        }
      },

      signOut: async () => {
        await apiClient.logout();
        notifyAuthChange("SIGNED_OUT", null);
        return { error: null };
      },

      getSession: async () => {
        const token = apiClient.getToken();
        const storedUser = apiClient.getStoredUser();
        if (!token || !storedUser) {
          return { data: { session: null }, error: null };
        }
        return { data: { session: buildSession(storedUser, token) }, error: null };
      },

      getUser: async () => {
        const token = apiClient.getToken();
        if (!token) {
          return { data: { user: null }, error: null };
        }
        try {
          const apiUser = await apiClient.getMe();
          return { data: { user: userToSupabaseUser(apiUser) }, error: null };
        } catch {
          return { data: { user: null }, error: null };
        }
      },

      onAuthStateChange: (callback: AuthListener) => {
        authListeners.add(callback);
        // Initial call with current session
        const token = apiClient.getToken();
        const storedUser = apiClient.getStoredUser();
        if (token && storedUser) {
          callback("SIGNED_IN", buildSession(storedUser, token));
        } else {
          callback("SIGNED_OUT", null);
        }
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
    },

    from: (table: string) => {
      let isSingle = false;
      let isMaybeSingle = false;
      const filters: Array<{ column: string; op: string; value: unknown }> = [];
      let orderCol: string | null = null;
      let orderAsc = true;
      let limitCount: number | null = null;

      const builder = {
        select: (_columns = "*") => builder,
        eq: (column: string, value: unknown) => {
          filters.push({ column, op: "eq", value });
          return builder;
        },
        in: (column: string, values: unknown[]) => {
          filters.push({ column, op: "in", value: values });
          return builder;
        },
        order: (column: string, options?: { ascending?: boolean }) => {
          orderCol = column;
          orderAsc = options?.ascending !== false;
          return builder;
        },
        limit: (count: number) => {
          limitCount = count;
          return builder;
        },
        single: () => {
          isSingle = true;
          return builder;
        },
        maybeSingle: () => {
          isMaybeSingle = true;
          return builder;
        },

        // Execution
        then: async (
          resolve: (val: { data: unknown; error: unknown }) => void,
          reject?: (err: unknown) => void,
        ) => {
          try {
            let data: unknown = null;

            if (table === "profiles") {
              const idFilter = filters.find((f) => f.column === "id")?.value as string | undefined;
              if (idFilter) {
                // Fetch profile for id
                const me = apiClient.getStoredUser();
                if (me && me.id === idFilter && me.profile) {
                  data = isSingle || isMaybeSingle ? me.profile : [me.profile];
                } else {
                  const recipients = await apiClient.listRecipients();
                  const found = recipients.find((r) => r.id === idFilter);
                  data = isSingle || isMaybeSingle ? found || null : found ? [found] : [];
                }
              } else {
                const recipients = await apiClient.listRecipients();
                data = recipients;
              }
            } else if (table === "user_keys") {
              const idFilter = filters.find((f) => f.column === "user_id")?.value as
                string | undefined;
              const me = apiClient.getStoredUser();
              if (idFilter && me && idFilter === me.id) {
                const myKey = await apiClient.getMyKeys().catch(() => null);
                data = isSingle || isMaybeSingle ? myKey : myKey ? [myKey] : [];
              } else if (idFilter) {
                const pubKey = await apiClient.getPublicKey(idFilter).catch(() => null);
                data = isSingle || isMaybeSingle ? pubKey : pubKey ? [pubKey] : [];
              } else {
                data = isSingle || isMaybeSingle ? null : [];
              }
            } else if (table === "transfers") {
              const idFilter = filters.find((f) => f.column === "id")?.value as string | undefined;
              if (idFilter) {
                const detail = await apiClient.getTransferDetail(idFilter);
                data = isSingle || isMaybeSingle ? detail : [detail];
              } else {
                const all = await apiClient.listTransfers();
                data = all;
              }
            } else if (table === "security_events") {
              data = await apiClient.listSecurityEvents(limitCount || 50);
            } else if (table === "threat_incidents") {
              data = await apiClient.listThreatIncidents(limitCount || 50);
            } else if (table === "trust_events") {
              data = await apiClient.getTrustEvents();
            } else if (table === "notifications") {
              data = await apiClient.listNotifications(limitCount || 20);
            } else if (table === "audit_logs") {
              data = await apiClient.getAuditLogs(limitCount || 100);
            } else if (table === "user_roles") {
              const me = apiClient.getStoredUser();
              const rolesList = (me?.roles || ["user"]).map((r) => ({ role: r }));
              data = isSingle || isMaybeSingle ? rolesList[0] || null : rolesList;
            } else {
              data = isSingle || isMaybeSingle ? null : [];
            }

            resolve({ data, error: null });
          } catch (err) {
            if (isMaybeSingle) {
              resolve({ data: null, error: null });
            } else {
              resolve({ data: null, error: { message: (err as Error).message } });
            }
          }
        },

        insert: (values: unknown) => {
          return {
            select: () => ({
              single: async () => {
                try {
                  const row = (Array.isArray(values) ? values[0] : values) as Record<
                    string,
                    unknown
                  >;
                  let result: unknown = row;
                  if (table === "transfers") {
                    result = await apiClient.createTransfer(
                      row as unknown as Parameters<typeof apiClient.createTransfer>[0],
                    );
                  } else if (table === "user_keys") {
                    result = await apiClient.registerKeys(
                      row as unknown as Parameters<typeof apiClient.registerKeys>[0],
                    );
                  } else if (table === "security_events") {
                    result = await apiClient.recordSecurityEvent(
                      row as unknown as Parameters<typeof apiClient.recordSecurityEvent>[0],
                    );
                  }
                  return { data: result, error: null };
                } catch (err) {
                  return { data: null, error: { message: (err as Error).message } };
                }
              },
            }),
            then: async (resolve: (val: { data: unknown; error: unknown }) => void) => {
              try {
                const row = (Array.isArray(values) ? values[0] : values) as Record<string, unknown>;
                let result: unknown = row;
                if (table === "transfers") {
                  result = await apiClient.createTransfer(
                    row as unknown as Parameters<typeof apiClient.createTransfer>[0],
                  );
                } else if (table === "user_keys") {
                  result = await apiClient.registerKeys(
                    row as unknown as Parameters<typeof apiClient.registerKeys>[0],
                  );
                } else if (table === "security_events") {
                  result = await apiClient.recordSecurityEvent(
                    row as unknown as Parameters<typeof apiClient.recordSecurityEvent>[0],
                  );
                }
                resolve({ data: result, error: null });
              } catch (err) {
                resolve({ data: null, error: { message: (err as Error).message } });
              }
            },
          };
        },

        update: (values: unknown) => {
          return {
            eq: (_column: string, _val: unknown) => ({
              then: async (resolve: (val: { data: unknown; error: unknown }) => void) => {
                try {
                  const row = values as Record<string, unknown>;
                  if (table === "profiles") {
                    await apiClient.updateProfile({
                      full_name: row["full_name"] as string,
                      organization: row["organization"] as string,
                    });
                  }
                  resolve({ data: row, error: null });
                } catch (err) {
                  resolve({ data: null, error: { message: (err as Error).message } });
                }
              },
            }),
          };
        },

        upsert: (values: unknown) => {
          return {
            select: () => ({
              single: async () => {
                try {
                  const row = (Array.isArray(values) ? values[0] : values) as Record<
                    string,
                    unknown
                  >;
                  let result: unknown = row;
                  if (table === "user_keys") {
                    result = await apiClient.registerKeys(
                      row as unknown as Parameters<typeof apiClient.registerKeys>[0],
                    );
                  }
                  return { data: result, error: null };
                } catch (err) {
                  return { data: null, error: { message: (err as Error).message } };
                }
              },
            }),
          };
        },
      };

      return builder;
    },

    storage: {
      from: (_bucket: string) => ({
        upload: async (path: string, file: Blob | Uint8Array) => {
          try {
            // path is typically `${transferId}.bin` or similar
            const transferId = path.split("/").pop()?.replace(".bin", "") || path;
            const res = await apiClient.uploadPayload(transferId, file, path);
            return { data: { path: res.storage_path }, error: null };
          } catch (err) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },

        download: async (path: string) => {
          try {
            const transferId = path.split("/").pop()?.replace(".bin", "") || path;
            const bytes = await apiClient.downloadPayload(transferId);
            const blob = new Blob([bytes as unknown as ArrayBuffer], {
              type: "application/octet-stream",
            });
            return { data: blob, error: null };
          } catch (err) {
            return { data: null, error: { message: (err as Error).message } };
          }
        },

        createSignedUrl: async (path: string, _expiresIn: number) => {
          const transferId = path.split("/").pop()?.replace(".bin", "") || path;
          return {
            data: { signedUrl: `/api/transfers/${transferId}/download` },
            error: null,
          };
        },
      }),
    },

    rpc: async (fnName: string, args?: Record<string, unknown>) => {
      try {
        if (fnName === "users_with_published_keys") {
          const recipients = await apiClient.listRecipients();
          return { data: recipients.map((r) => ({ user_id: r.id })), error: null };
        }
        if (fnName === "has_role") {
          const me = apiClient.getStoredUser();
          const role = args?.["_role"] as string;
          const has = me?.roles.includes(role) ?? false;
          return { data: has, error: null };
        }
        return { data: null, error: null };
      } catch (err) {
        return { data: null, error: { message: (err as Error).message } };
      }
    },
  };
}
