/**
 * The single receiver-side download gate.
 *
 * Both the production `requestDownload` server function and the Controlled
 * Security Testing Lab call this exact function, so a lab scenario exercises the
 * real authorisation, token, expiry, replay, limit and session checks — nothing
 * is faked at the UI layer.
 */
import { isDownloadable, downloadBlockReason } from "./transfer-state";
import {
  logAudit,
  raiseThreat,
  sha256HexServer,
  timingSafeEqualHex,
  type Admin,
  type ThreatResult,
} from "./security.server";

export type GateInput = {
  transferId: string;
  /** The authenticated account performing the request (never trusted from the client). */
  actorId: string;
  token: string;
  ip: string;
  deviceFingerprint: string;
  /** Lab scenarios evaluate the gate without minting a payload URL. */
  issueSignedUrl?: boolean;
  simulated?: boolean;
  receiverLatitude?: number | null | undefined;
  receiverLongitude?: number | null | undefined;
  receiverLocationTimestamp?: string | null | undefined;
};

export type GateDenied = {
  ok: false;
  stage: string;
  reason: string;
  threat: ThreatResult | null;
};

export type GateAllowed = {
  ok: true;
  signedUrl: string | null;
  wrappedKey: string | null;
  iv: string;
  expectedHash: string;
  ciphertextHash: string;
};

export type GateResult = GateAllowed | GateDenied;

export async function evaluateDownloadGate(admin: Admin, input: GateInput): Promise<GateResult> {
  const { actorId, ip, simulated = false } = input;
  const issueSignedUrl = input.issueSignedUrl ?? true;

  const { data: transfer } = await admin
    .from("transfers")
    .select("*")
    .eq("id", input.transferId)
    .maybeSingle();
  if (!transfer) throw new Error("Transfer not found.");

  const deny = async (
    type: Parameters<typeof raiseThreat>[1]["type"],
    stage: string,
    reason: string,
    details: Record<string, unknown> = {},
  ): Promise<GateDenied> => {
    await logAudit(admin, {
      userId: actorId,
      transferId: transfer.id,
      event: "ACCESS_BLOCKED",
      severity: "high",
      ip,
      action: stage,
      metadata: { simulated, ...details },
    });
    const threat = await raiseThreat(admin, {
      type,
      userId: actorId,
      transferId: transfer.id,
      ip,
      simulated,
      details: { stage, deviceFingerprint: input.deviceFingerprint, ...details },
    });
    return { ok: false, stage, reason, threat };
  };

  // 1. Authorisation — is the caller the designated recipient?
  if (transfer.recipient_id !== actorId) {
    await logAudit(admin, {
      userId: actorId,
      transferId: transfer.id,
      event: "UNAUTHORIZED_ACCESS_ATTEMPT",
      severity: "high",
      ip,
      action: "RECIPIENT_MISMATCH",
      metadata: { simulated },
    });
    return deny(
      "UNAUTHORIZED_RECEIVER",
      "AUTHORIZATION",
      "The authenticated account is not the designated recipient.",
      { attemptedBy: actorId },
    );
  }

  // 1b. Receiver Trust Score evaluation
  const { data: receiverProfile } = await admin
    .from("profiles")
    .select("trust_score")
    .eq("id", actorId)
    .maybeSingle();
  if ((receiverProfile?.trust_score ?? 100) < 60) {
    return deny(
      "UNAUTHORIZED_RECEIVER",
      "TRUST_EVALUATION",
      "Access blocked because receiver account trust score is below the required security threshold (60).",
      { trustScore: receiverProfile?.trust_score ?? 100, threshold: 60 },
    );
  }

  if (transfer.status === "TERMINATED")
    return deny("INVALID_TOKEN", "STATE", "This transfer was terminated by the threat engine.", {
      reason: "transfer already terminated",
    });

  if (!isDownloadable(transfer.status)) {
    await logAudit(admin, {
      userId: actorId,
      transferId: transfer.id,
      event: "DOWNLOAD_REJECTED",
      severity: "medium",
      ip,
      action: "STATE_NOT_DOWNLOADABLE",
      metadata: { status: transfer.status, simulated },
    });
    throw new Error(downloadBlockReason(transfer.status) ?? "This transfer is not downloadable.");
  }

  await logAudit(admin, {
    userId: actorId,
    transferId: transfer.id,
    event: "RECEIVER_ACCESS",
    ip,
    action: "RECIPIENT_AUTHENTICATED",
    metadata: { deviceFingerprint: input.deviceFingerprint, simulated },
  });

  // 2. Token validation against the stored hash (constant-time).
  const presented = await sha256HexServer(input.token);
  if (!timingSafeEqualHex(presented, transfer.token_hash)) {
    const attempts = transfer.failed_attempts + 1;
    await admin.from("transfers").update({ failed_attempts: attempts }).eq("id", transfer.id);
    await logAudit(admin, {
      userId: actorId,
      transferId: transfer.id,
      event: "TOKEN_VALIDATION_FAILED",
      severity: "high",
      ip,
      action: "TOKEN_HASH_MISMATCH",
      metadata: { attempts, simulated },
    });
    if (attempts >= 3)
      await raiseThreat(admin, {
        type: "EXCESSIVE_FAILED_DOWNLOADS",
        userId: actorId,
        transferId: transfer.id,
        ip,
        simulated,
        details: { attempts },
      });
    return deny("INVALID_TOKEN", "TOKEN", "The presented access token is invalid.", { attempts });
  }

  await logAudit(admin, {
    userId: actorId,
    transferId: transfer.id,
    event: "TOKEN_VALIDATED",
    ip,
    action: "TOKEN_HASH_MATCH",
    metadata: { simulated },
  });

  // 3. Expiry.
  if (new Date(transfer.expires_at).getTime() < Date.now()) {
    await admin.from("transfers").update({ status: "EXPIRED" }).eq("id", transfer.id);
    return deny("TRANSFER_EXPIRED", "EXPIRY", "This transfer has passed its expiry time.", {
      expiredAt: transfer.expires_at,
    });
  }

  // 4. Download limit.
  if (transfer.download_count >= transfer.max_downloads)
    return deny(
      "DOWNLOAD_LIMIT_EXCEEDED",
      "DOWNLOAD_LIMIT",
      "The configured download limit for this transfer has been reached.",
      { downloads: transfer.download_count, limit: transfer.max_downloads },
    );

  // 5. One-time token replay.
  if (transfer.max_downloads === 1 && transfer.token_used_at)
    return deny("TOKEN_REPLAY", "REPLAY", "This one-time token was already consumed.", {
      firstUse: transfer.token_used_at,
    });

  // 6. Session / device / network evidence.
  const nowIso = new Date().toISOString();
  const { data: session } = await admin
    .from("app_sessions")
    .select("id, expires_at, revoked, ip_address, device_fingerprint")
    .eq("user_id", actorId)
    .eq("revoked", false)
    .gt("expires_at", nowIso)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();
  if (!session)
    return deny("EXPIRED_SESSION", "SESSION", "No active application session for this account.", {
      checkedAt: nowIso,
    });
  if (session.ip_address && session.ip_address !== ip)
    await raiseThreat(admin, {
      type: "SUSPICIOUS_IP_CHANGE",
      userId: actorId,
      transferId: transfer.id,
      ip,
      simulated,
      details: { sessionIp: session.ip_address, requestIp: ip },
    });

  // 7. Request-rate anomaly.
  const since = new Date(Date.now() - 60_000).toISOString();
  const { count } = await admin
    .from("audit_logs")
    .select("id", { count: "exact", head: true })
    .eq("user_id", actorId)
    .eq("transfer_id", transfer.id)
    .eq("event", "DOWNLOAD_STARTED")
    .gte("created_at", since);
  if ((count ?? 0) > 10)
    await raiseThreat(admin, {
      type: "ABNORMAL_REQUEST_RATE",
      userId: actorId,
      transferId: transfer.id,
      ip,
      simulated,
      details: { requestsLastMinute: count },
    });

  let signedUrl: string | null = null;
  if (issueSignedUrl) {
    const { data: signed, error: signedError } = await admin.storage
      .from("encrypted-payloads")
      .createSignedUrl(transfer.storage_path!, 60);
    if (signedError || !signed) throw new Error("Encrypted payload is unavailable.");
    signedUrl = signed.signedUrl;
  }

  const { data: keyRow } = await admin
    .from("transfer_keys")
    .select("wrapped_key")
    .eq("transfer_id", transfer.id)
    .maybeSingle();

  const updatePayload: Record<string, unknown> = {
    status: "VERIFYING",
    download_count: transfer.download_count + 1,
    token_used_at: transfer.token_used_at ?? nowIso,
  };
  if (
    typeof input.receiverLatitude === "number" &&
    typeof input.receiverLongitude === "number" &&
    input.receiverLatitude >= -90 &&
    input.receiverLatitude <= 90 &&
    input.receiverLongitude >= -180 &&
    input.receiverLongitude <= 180
  ) {
    updatePayload["receiver_latitude"] = input.receiverLatitude;
    updatePayload["receiver_longitude"] = input.receiverLongitude;
    updatePayload["receiver_location_timestamp"] = input.receiverLocationTimestamp ?? nowIso;
  }

  await admin
    .from("transfers")
    .update(updatePayload as never)
    .eq("id", transfer.id);

  await logAudit(admin, {
    userId: actorId,
    transferId: transfer.id,
    event: "DOWNLOAD_STARTED",
    ip,
    action: issueSignedUrl ? "SIGNED_URL_ISSUED" : "GATE_PASSED",
    metadata: { ttlSeconds: 60, simulated },
  });

  return {
    ok: true,
    signedUrl,
    wrappedKey: keyRow?.wrapped_key ?? null,
    iv: transfer.iv,
    expectedHash: transfer.original_sha256,
    ciphertextHash: transfer.ciphertext_sha256,
  };
}
