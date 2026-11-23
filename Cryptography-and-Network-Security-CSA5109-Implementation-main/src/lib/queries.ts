import { useQuery } from "@tanstack/react-query";

import { supabase } from "@/integrations/supabase/client";

export type FileMeta = {
  original_name: string;
  size_bytes: number;
  mime_type: string;
  extension: string | null;
};

export type TransferRecord = {
  id: string;
  sender_id: string;
  recipient_id: string;
  status: string;
  security_level: string;
  storage_path: string | null;
  iv: string;
  original_sha256: string;
  ciphertext_sha256: string;
  expires_at: string;
  max_downloads: number;
  download_count: number;
  failed_attempts: number;
  token_used_at: string | null;
  sender_token_wrapped: string | null;
  terminated_reason: string | null;
  metrics: Record<string, number> | null;
  created_at: string;
  file_metadata: FileMeta[] | null;
};

export type ProfileLite = {
  id: string;
  email: string;
  full_name: string | null;
  trust_score: number;
  status: string;
  created_at: string;
};

const TRANSFER_SELECT = "*, file_metadata(original_name, size_bytes, mime_type, extension)";

export function firstFile(t: { file_metadata: FileMeta[] | null }): FileMeta | null {
  return t.file_metadata?.[0] ?? null;
}

export function useProfiles() {
  return useQuery({
    queryKey: ["profiles"],
    queryFn: async (): Promise<ProfileLite[]> => {
      const { data, error } = await supabase
        .from("profiles")
        .select("id, email, full_name, trust_score, status, created_at");
      if (error) throw new Error(error.message);
      return (data ?? []) as ProfileLite[];
    },
  });
}

export function useProfileMap() {
  const q = useProfiles();
  const map = new Map<string, ProfileLite>();
  for (const p of q.data ?? []) map.set(p.id, p);
  return { ...q, map };
}

export function useTransfers(userId: string | undefined, direction: "sent" | "received" | "all") {
  return useQuery({
    queryKey: ["transfers", userId, direction],
    enabled: Boolean(userId),
    queryFn: async (): Promise<TransferRecord[]> => {
      let query = supabase
        .from("transfers")
        .select(TRANSFER_SELECT)
        .order("created_at", { ascending: false });
      if (direction === "sent") query = query.eq("sender_id", userId!);
      if (direction === "received") query = query.eq("recipient_id", userId!);
      const { data, error } = await query;
      if (error) throw new Error(error.message);
      return (data ?? []) as unknown as TransferRecord[];
    },
  });
}

export function useTransfer(id: string) {
  return useQuery({
    queryKey: ["transfer", id],
    queryFn: async (): Promise<TransferRecord | null> => {
      const { data, error } = await supabase
        .from("transfers")
        .select(TRANSFER_SELECT)
        .eq("id", id)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return (data as unknown as TransferRecord) ?? null;
    },
  });
}

export type AuditRecord = {
  id: string;
  created_at: string;
  event: string;
  severity: string;
  ip_address: string | null;
  action: string | null;
  transfer_id: string | null;
  user_id: string | null;
  metadata: unknown;
};

export function useAuditLogs(options: { transferId?: string; limit?: number } = {}) {
  const { transferId, limit = 200 } = options;
  return useQuery({
    queryKey: ["audit", transferId ?? "all", limit],
    queryFn: async (): Promise<AuditRecord[]> => {
      let query = supabase
        .from("audit_logs")
        .select(
          "id, created_at, event, severity, ip_address, action, transfer_id, user_id, metadata",
        )
        .order("created_at", { ascending: false })
        .limit(limit);
      if (transferId) query = query.eq("transfer_id", transferId);
      const { data, error } = await query;
      if (error) throw new Error(error.message);
      return (data ?? []) as AuditRecord[];
    },
  });
}

export type SecurityEventRecord = {
  id: string;
  created_at: string;
  event_type: string;
  severity: string;
  trust_delta: number;
  simulated: boolean;
  transfer_id: string | null;
  user_id: string | null;
  ip_address: string | null;
};

export function useSecurityEvents(limit = 100) {
  return useQuery({
    queryKey: ["security-events", limit],
    queryFn: async (): Promise<SecurityEventRecord[]> => {
      const { data, error } = await supabase
        .from("security_events")
        .select(
          "id, created_at, event_type, severity, trust_delta, simulated, transfer_id, user_id, ip_address",
        )
        .order("created_at", { ascending: false })
        .limit(limit);
      if (error) throw new Error(error.message);
      return (data ?? []) as SecurityEventRecord[];
    },
  });
}

export type IncidentRecord = {
  id: string;
  created_at: string;
  threat_type: string;
  severity: string;
  action_taken: string;
  trust_delta: number;
  blocked: boolean;
  simulated: boolean;
  resolved: boolean;
  transfer_id: string | null;
  user_id: string | null;
  details: unknown;
};

export function useIncidents(limit = 100) {
  return useQuery({
    queryKey: ["incidents", limit],
    queryFn: async (): Promise<IncidentRecord[]> => {
      const { data, error } = await supabase
        .from("threat_incidents")
        .select(
          "id, created_at, threat_type, severity, action_taken, trust_delta, blocked, simulated, resolved, transfer_id, user_id, details",
        )
        .order("created_at", { ascending: false })
        .limit(limit);
      if (error) throw new Error(error.message);
      return (data ?? []) as IncidentRecord[];
    },
  });
}

export type NotificationRecord = {
  id: string;
  title: string;
  body: string;
  severity: string;
  read: boolean;
  created_at: string;
  transfer_id: string | null;
};

export function useNotifications(userId: string | undefined) {
  return useQuery({
    queryKey: ["notifications", userId],
    enabled: Boolean(userId),
    refetchInterval: 30_000,
    queryFn: async (): Promise<NotificationRecord[]> => {
      const { data, error } = await supabase
        .from("notifications")
        .select("id, title, body, severity, read, created_at, transfer_id")
        .order("created_at", { ascending: false })
        .limit(30);
      if (error) throw new Error(error.message);
      return (data ?? []) as NotificationRecord[];
    },
  });
}

export type SessionRecord = {
  id: string;
  created_at: string;
  last_active: string;
  expires_at: string;
  revoked: boolean;
  revoked_reason: string | null;
  ip_address: string | null;
  device_fingerprint: string | null;
  user_agent: string | null;
};

export function useSessions(userId: string | undefined) {
  return useQuery({
    queryKey: ["sessions", userId],
    enabled: Boolean(userId),
    queryFn: async (): Promise<SessionRecord[]> => {
      const { data, error } = await supabase
        .from("app_sessions")
        .select(
          "id, created_at, last_active, expires_at, revoked, revoked_reason, ip_address, device_fingerprint, user_agent",
        )
        .eq("user_id", userId!)
        .order("created_at", { ascending: false })
        .limit(20);
      if (error) throw new Error(error.message);
      return (data ?? []) as SessionRecord[];
    },
  });
}

export type TransferKeyRecord = {
  id: string;
  wrap_algorithm: string;
  created_at: string;
};

export function useTransferKeys(transferId: string | undefined) {
  return useQuery({
    queryKey: ["transfer-keys", transferId],
    enabled: Boolean(transferId),
    queryFn: async (): Promise<TransferKeyRecord[]> => {
      const { data, error } = await supabase
        .from("transfer_keys")
        .select("id, wrap_algorithm, created_at")
        .eq("transfer_id", transferId!);
      if (error) throw new Error(error.message);
      return (data ?? []) as TransferKeyRecord[];
    },
  });
}

export function useTransferMetadata(transferId: string | undefined) {
  return useQuery({
    queryKey: ["transfer-metadata", transferId],
    enabled: Boolean(transferId),
    queryFn: async (): Promise<FileMeta | null> => {
      const { data, error } = await supabase
        .from("file_metadata")
        .select("original_name, size_bytes, mime_type, extension")
        .eq("transfer_id", transferId!)
        .maybeSingle();
      if (error) throw new Error(error.message);
      return (data as FileMeta) ?? null;
    },
  });
}

export function useTransferNotifications(transferId: string | undefined) {
  return useQuery({
    queryKey: ["transfer-notifications", transferId],
    enabled: Boolean(transferId),
    queryFn: async (): Promise<NotificationRecord[]> => {
      const { data, error } = await supabase
        .from("notifications")
        .select("id, title, body, severity, read, created_at, transfer_id")
        .eq("transfer_id", transferId!)
        .order("created_at", { ascending: false });
      if (error) throw new Error(error.message);
      return (data ?? []) as NotificationRecord[];
    },
  });
}

export type DeviceRecord = {
  id: string;
  fingerprint: string;
  user_agent: string | null;
  first_seen: string;
  last_seen: string;
  trusted: boolean;
};

export function useDevices(userId: string | undefined) {
  return useQuery({
    queryKey: ["devices", userId],
    enabled: Boolean(userId),
    queryFn: async (): Promise<DeviceRecord[]> => {
      const { data, error } = await supabase
        .from("devices")
        .select("id, fingerprint, user_agent, first_seen, last_seen, trusted")
        .eq("user_id", userId!)
        .order("last_seen", { ascending: false });
      if (error) throw new Error(error.message);
      return (data ?? []) as DeviceRecord[];
    },
  });
}
