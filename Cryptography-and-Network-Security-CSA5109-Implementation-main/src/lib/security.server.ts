/**
 * Server-side security engine: audit logging, threat response, trust scoring.
 * Never imported by client code (blocked by the *.server.* filename rule).
 */
import type { SupabaseClient } from "@supabase/supabase-js";

import {
  THREAT_RULES,
  applyTrustDelta,
  getTrustStatus,
  isTransferEligible,
  type ThreatType,
  type TrustStatus,
} from "./security-rules";
import type { Database } from "@/integrations/supabase/types";

export type Admin = SupabaseClient<Database>;

export async function getAdmin(): Promise<Admin> {
  const { createAdminClient } = await import("./supabase-admin.server");
  return createAdminClient() as unknown as Admin;
}

export async function logAudit(
  admin: Admin,
  entry: {
    userId: string | null;
    transferId?: string | null;
    event: string;
    severity?: string;
    ip?: string | null;
    action?: string | null;
    metadata?: Record<string, unknown>;
  },
) {
  await admin.from("audit_logs").insert({
    user_id: entry.userId,
    transfer_id: entry.transferId ?? null,
    event: entry.event,
    severity: entry.severity ?? "info",
    ip_address: entry.ip ?? null,
    action: entry.action ?? null,
    metadata: (entry.metadata ?? {}) as never,
  });
}

export async function notify(
  admin: Admin,
  userId: string,
  transferId: string | null,
  title: string,
  body: string,
  severity = "info",
) {
  await admin
    .from("notifications")
    .insert({ user_id: userId, transfer_id: transferId, title, body, severity });
}

export type ThreatResult = {
  type: ThreatType;
  label: string;
  severity: string;
  action: string;
  trustDelta: number;
  blocked: boolean;
  newTrustScore: number;
  trustStatus: TrustStatus;
  isEligible: boolean;
  simulated: boolean;
};

/**
 * Single entry point for every detected threat — real or DEMO SIMULATION.
 * Applies: incident record, security event, trust event history, trust deduction,
 * transfer state change, session revocation and notifications.
 */
export async function raiseThreat(
  admin: Admin,
  input: {
    type: ThreatType;
    userId: string;
    transferId?: string | null;
    ip?: string | null;
    simulated?: boolean;
    details?: Record<string, unknown>;
  },
): Promise<ThreatResult> {
  const rule = THREAT_RULES[input.type];
  const simulated = input.simulated ?? false;
  const transferId = input.transferId ?? null;

  const { data: profile } = await admin
    .from("profiles")
    .select("trust_score")
    .eq("id", input.userId)
    .maybeSingle();

  const previousScore = profile?.trust_score ?? 100;
  const newScore = applyTrustDelta(previousScore, rule.trustDelta);
  const trustStatus = getTrustStatus(newScore);
  const nowIso = new Date().toISOString();

  await admin
    .from("profiles")
    .update({
      trust_score: newScore,
      trust_status: trustStatus,
      trust_updated_at: nowIso,
    })
    .eq("id", input.userId);

  await admin.from("threat_incidents").insert({
    user_id: input.userId,
    transfer_id: transferId,
    threat_type: rule.type,
    severity: rule.severity,
    action_taken: rule.action,
    trust_delta: rule.trustDelta,
    blocked: rule.blocksTransfer,
    simulated,
    details: { ...(input.details ?? {}), rule: rule.description } as never,
  });

  const { data: eventRow } = await admin
    .from("security_events")
    .insert({
      user_id: input.userId,
      transfer_id: transferId,
      event_type: rule.type,
      severity: rule.severity,
      ip_address: input.ip ?? null,
      trust_delta: rule.trustDelta,
      simulated,
      metadata: { action: rule.action, ...(input.details ?? {}) } as never,
    })
    .select("id")
    .maybeSingle();

  // Audit every single trust score mutation in trust_events
  await admin.from("trust_events").insert({
    user_id: input.userId,
    security_event_id: eventRow?.id ?? null,
    previous_score: previousScore,
    delta: rule.trustDelta,
    new_score: newScore,
    reason: `${rule.label}: ${rule.description}`,
  });

  await logAudit(admin, {
    userId: input.userId,
    transferId,
    event: `THREAT_${rule.type}`,
    severity: rule.severity,
    ip: input.ip ?? null,
    action: rule.action,
    metadata: {
      simulated,
      previousScore,
      trustDelta: rule.trustDelta,
      newTrustScore: newScore,
      trustStatus,
      ...(input.details ?? {}),
    },
  });

  if (transferId) {
    let nextStatus: string | null = null;
    if (rule.action === "TERMINATE_TRANSFER") nextStatus = "TERMINATED";
    else if (rule.action === "PAUSE_TRANSFER") nextStatus = "PAUSED";
    else if (rule.severity === "medium") nextStatus = "SUSPICIOUS";

    const { data: transfer } = await admin
      .from("transfers")
      .select("id, sender_id, recipient_id, status")
      .eq("id", transferId)
      .maybeSingle();

    if (transfer && nextStatus && transfer.status !== "TERMINATED") {
      await admin
        .from("transfers")
        .update({ status: nextStatus, terminated_reason: `${rule.type}: ${rule.action}` })
        .eq("id", transferId);
    }
    if (transfer) {
      const prefix = simulated ? "[DEMO SIMULATION] " : "";
      if (rule.notifySender)
        await notify(
          admin,
          transfer.sender_id,
          transferId,
          `${prefix}${rule.label}`,
          `${rule.description} Response: ${rule.action.replace(/_/g, " ").toLowerCase()}.`,
          rule.severity,
        );
      if (rule.notifyReceiver)
        await notify(
          admin,
          transfer.recipient_id,
          transferId,
          `${prefix}${rule.label}`,
          `${rule.description} Response: ${rule.action.replace(/_/g, " ").toLowerCase()}.`,
          rule.severity,
        );
    }
  }

  if (rule.action === "REVOKE_SESSION") {
    await admin
      .from("app_sessions")
      .update({ revoked: true, revoked_reason: rule.type })
      .eq("user_id", input.userId)
      .eq("revoked", false);
  }

  return {
    type: rule.type,
    label: rule.label,
    severity: rule.severity,
    action: rule.action,
    trustDelta: rule.trustDelta,
    blocked: rule.blocksTransfer,
    newTrustScore: newScore,
    trustStatus,
    isEligible: isTransferEligible(newScore),
    simulated,
  };
}

export async function sha256HexServer(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function timingSafeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export async function isAdmin(admin: Admin, userId: string): Promise<boolean> {
  const { data } = await admin
    .from("user_roles")
    .select("role")
    .eq("user_id", userId)
    .eq("role", "admin")
    .maybeSingle();
  return Boolean(data);
}
