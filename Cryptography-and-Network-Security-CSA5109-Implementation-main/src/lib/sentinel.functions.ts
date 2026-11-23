import { createServerFn } from "@tanstack/react-start";
import { getRequestIP, getRequestHeader } from "@tanstack/react-start/server";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import {
  createTransferSchema,
  downloadSchema,
  integritySchema,
  sessionSchema,
  logEventSchema,
  simulateSchema,
  loginAttemptSchema,
  adminActionSchema,
} from "./sentinel.schemas";
import { downloadBlockReason, isDownloadable } from "./transfer-state";

function clientIp(): string {
  return getRequestIP({ xForwardedFor: true }) ?? getRequestHeader("x-forwarded-for") ?? "unknown";
}

/** Registers the device + application session and runs session-level detection. */
export const startSession = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => sessionSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, logAudit, raiseThreat } = await import("./security.server");
    const admin = await getAdmin();
    const ip = clientIp();
    const userId = context.userId;
    const ua = getRequestHeader("user-agent") ?? null;

    const { data: knownDevices } = await admin
      .from("devices")
      .select("id, fingerprint")
      .eq("user_id", userId);

    const existingDevice =
      (knownDevices ?? []).find((d) => d.fingerprint === data.deviceFingerprint) ?? null;
    // A user's very first device is enrolled, not treated as a device change.
    const isFirstEverDevice = (knownDevices ?? []).length === 0;

    if (existingDevice) {
      await admin
        .from("devices")
        .update({ last_seen: new Date().toISOString() })
        .eq("id", existingDevice.id);
    } else {
      await admin.from("devices").insert({
        user_id: userId,
        fingerprint: data.deviceFingerprint,
        user_agent: ua,
        trusted: isFirstEverDevice,
      });
    }

    const nowIso = new Date().toISOString();
    await admin
      .from("app_sessions")
      .update({ revoked: true, revoked_reason: "EXPIRED" })
      .eq("user_id", userId)
      .eq("revoked", false)
      .lt("expires_at", nowIso);

    const { data: active } = await admin
      .from("app_sessions")
      .select("id, ip_address, device_fingerprint")
      .eq("user_id", userId)
      .eq("revoked", false)
      .gt("expires_at", nowIso);

    // Sessions belonging to this same device are the same browser reconnecting —
    // only *other* devices count as concurrent or anomalous.
    const otherDeviceSessions = (active ?? []).filter(
      (s) => s.device_fingerprint !== data.deviceFingerprint,
    );
    const sameDeviceSession = (active ?? []).find(
      (s) => s.device_fingerprint === data.deviceFingerprint,
    );

    const threats: string[] = [];
    if (!existingDevice && !isFirstEverDevice) {
      await raiseThreat(admin, {
        type: "DEVICE_CHANGE",
        userId,
        ip,
        details: { fingerprint: data.deviceFingerprint },
      });
      threats.push("DEVICE_CHANGE");
    }
    if (otherDeviceSessions.length >= 1) {
      await raiseThreat(admin, {
        type: "CONCURRENT_SESSIONS",
        userId,
        ip,
        details: { count: otherDeviceSessions.length + 1 },
      });
      threats.push("CONCURRENT_SESSIONS");
    }
    if (otherDeviceSessions.some((s) => s.ip_address && s.ip_address !== ip)) {
      await raiseThreat(admin, {
        type: "SUSPICIOUS_IP_CHANGE",
        userId,
        ip,
        details: { observed: ip },
      });
      threats.push("SUSPICIOUS_IP_CHANGE");
    }

    // Reuse the live session for this device instead of stacking new rows on
    // every page load; otherwise normal navigation looks like session sprawl.
    let session: { id: string; expires_at: string } | null = null;
    if (sameDeviceSession) {
      const { data: refreshed } = await admin
        .from("app_sessions")
        .update({ last_active: nowIso, ip_address: ip, user_agent: ua })
        .eq("id", sameDeviceSession.id)
        .select("id, expires_at")
        .single();
      session = refreshed ?? null;
    } else {
      const { data: created } = await admin
        .from("app_sessions")
        .insert({
          user_id: userId,
          device_fingerprint: data.deviceFingerprint,
          ip_address: ip,
          user_agent: ua,
        })
        .select("id, expires_at")
        .single();
      session = created ?? null;
    }

    await logAudit(admin, { userId, event: "USER_LOGIN", ip, action: "SESSION_ESTABLISHED" });

    const { data: profile } = await admin
      .from("profiles")
      .select("trust_score, status")
      .eq("id", userId)
      .maybeSingle();

    return {
      sessionId: session?.id ?? null,
      expiresAt: session?.expires_at ?? null,
      ip,
      trustScore: profile?.trust_score ?? 100,
      status: profile?.status ?? "active",
      threats,
    };
  });

export const endSession = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getAdmin, logAudit } = await import("./security.server");
    const admin = await getAdmin();
    await admin
      .from("app_sessions")
      .update({ revoked: true, revoked_reason: "USER_LOGOUT" })
      .eq("user_id", context.userId)
      .eq("revoked", false);
    await logAudit(admin, {
      userId: context.userId,
      event: "USER_LOGOUT",
      ip: clientIp(),
      action: "SESSION_CLOSED",
    });
    return { ok: true };
  });

/** Generic audit hook used by the client for lifecycle events. */
export const logEvent = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => logEventSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, logAudit } = await import("./security.server");
    const admin = await getAdmin();
    await logAudit(admin, {
      userId: context.userId,
      transferId: data.transferId ?? null,
      event: data.event,
      severity: data.severity,
      ip: clientIp(),
      action: data.action ?? null,
      metadata: data.metadata ?? {},
    });
    return { ok: true };
  });

/** Persists an encrypted transfer. The plaintext token is returned exactly once. */
/** Persists an encrypted transfer. The plaintext token is returned exactly once. */
export const createTransfer = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => createTransferSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, logAudit, notify, sha256HexServer } = await import("./security.server");
    const admin = await getAdmin();
    const ip = clientIp();
    const senderId = context.userId;

    if (data.recipientId === senderId) throw new Error("You cannot send a transfer to yourself.");

    const { data: recipient } = await admin
      .from("profiles")
      .select("id, email, full_name, status, trust_score")
      .eq("id", data.recipientId)
      .maybeSingle();
    if (!recipient) throw new Error("Recipient account not found.");
    if (recipient.status !== "active") throw new Error("Recipient account is suspended.");

    // Server-side enforcement of Trust Score threshold
    const recipientTrust = recipient.trust_score ?? 100;
    if (recipientTrust < 60) {
      await logAudit(admin, {
        userId: senderId,
        event: "TRANSFER_BLOCKED_LOW_TRUST",
        severity: "high",
        ip,
        action: "RECEIVER_TRUST_BELOW_THRESHOLD",
        metadata: {
          recipientId: data.recipientId,
          recipientTrustScore: recipientTrust,
          requiredThreshold: 60,
        },
      });
      throw new Error(
        "Transfer blocked because the selected receiver has a Trust Score below the required security threshold (60).",
      );
    }

    const hasSenderLocation =
      typeof data.senderLatitude === "number" &&
      typeof data.senderLongitude === "number" &&
      data.senderLatitude >= -90 &&
      data.senderLatitude <= 90 &&
      data.senderLongitude >= -180 &&
      data.senderLongitude <= 180;

    const token = data.token;
    const tokenHash = await sha256HexServer(token);
    const expiresAt = new Date(Date.now() + data.expiresInHours * 3600_000).toISOString();

    const { data: transfer, error } = await admin
      .from("transfers")
      .insert({
        sender_id: senderId,
        recipient_id: data.recipientId,
        status: "ENCRYPTED",
        security_level: data.securityLevel,
        storage_path: data.storagePath,
        iv: data.iv,
        original_sha256: data.originalSha256,
        ciphertext_sha256: data.ciphertextSha256,
        token_hash: tokenHash,
        sender_token_wrapped: data.senderTokenWrapped ?? null,
        expires_at: expiresAt,
        max_downloads: data.maxDownloads,
        metrics: data.metrics as never,
        sender_latitude: hasSenderLocation ? (data.senderLatitude ?? null) : null,
        sender_longitude: hasSenderLocation ? (data.senderLongitude ?? null) : null,
        sender_location_timestamp: hasSenderLocation
          ? (data.senderLocationTimestamp ?? new Date().toISOString())
          : null,
      })
      .select("*")
      .single();
    if (error || !transfer) throw new Error(error?.message ?? "Could not create transfer.");

    await admin
      .from("transfer_keys")
      .insert({ transfer_id: transfer.id, wrapped_key: data.wrappedKey });
    await admin.from("file_metadata").insert({
      transfer_id: transfer.id,
      original_name: data.fileName,
      mime_type: data.mimeType,
      size_bytes: data.sizeBytes,
      extension: data.fileName.split(".").pop() ?? null,
    });

    for (const event of [
      "FILE_SELECTED",
      "ENCRYPTION_STARTED",
      "ENCRYPTION_COMPLETED",
      "HASH_GENERATED",
      "KEY_WRAPPED",
      "TRANSFER_CREATED",
    ]) {
      await logAudit(admin, {
        userId: senderId,
        transferId: transfer.id,
        event,
        ip,
        action: "SECURE_SEND",
        metadata: {
          fileName: data.fileName,
          sizeBytes: data.sizeBytes,
          metrics: data.metrics,
          locationCaptured: hasSenderLocation,
        },
      });
    }

    await admin.from("transfers").update({ status: "TRANSFERRING" }).eq("id", transfer.id);
    await logAudit(admin, {
      userId: senderId,
      transferId: transfer.id,
      event: "TRANSFER_STARTED",
      ip,
    });

    await notify(
      admin,
      data.recipientId,
      transfer.id,
      "New secure transfer received",
      `${data.fileName} is waiting in your inbox. AES-256-GCM encrypted, key wrapped with your RSA public key.`,
    );

    return { transferId: transfer.id, token, expiresAt };
  });

/**
 * Receiver-side gate. Validates token, expiry, download limit, authorisation,
 * receiver trust score, and session/device/IP anomalies before issuing a short-lived signed URL.
 */
export const requestDownload = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => downloadSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin } = await import("./security.server");
    const { evaluateDownloadGate } = await import("./download-gate.server");
    const admin = await getAdmin();

    const result = await evaluateDownloadGate(admin, {
      transferId: data.transferId,
      actorId: context.userId,
      token: data.token,
      ip: clientIp(),
      deviceFingerprint: data.deviceFingerprint,
      receiverLatitude: data.receiverLatitude ?? null,
      receiverLongitude: data.receiverLongitude ?? null,
      receiverLocationTimestamp: data.receiverLocationTimestamp ?? null,
      issueSignedUrl: true,
    });

    if (!result.ok) return { ok: false as const, threat: result.threat };
    return {
      ok: true as const,
      signedUrl: result.signedUrl,
      wrappedKey: result.wrappedKey,
      iv: result.iv,
      expectedHash: result.expectedHash,
      ciphertextHash: result.ciphertextHash,
    };
  });

/** Receiver reports the SHA-256 of the decrypted file; the server is the judge. */
export const reportIntegrity = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => integritySchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, logAudit, raiseThreat, notify } = await import("./security.server");
    const admin = await getAdmin();
    const ip = clientIp();
    const userId = context.userId;

    const { data: transfer } = await admin
      .from("transfers")
      .select("*")
      .eq("id", data.transferId)
      .maybeSingle();
    if (!transfer) throw new Error("Transfer not found.");
    if (transfer.recipient_id !== userId) throw new Error("Not authorised for this transfer.");
    // Terminal states (TERMINATED / EXPIRED / FAILED / COMPLETED) can never be
    // resurrected into COMPLETED. Only an in-flight transfer may be verified.
    if (transfer.status !== "VERIFYING" && transfer.status !== "TRANSFERRING") {
      await logAudit(admin, {
        userId,
        transferId: transfer.id,
        event: "INTEGRITY_REPORT_REJECTED",
        severity: "high",
        ip,
        action: "STATE_LOCKED",
        metadata: { status: transfer.status },
      });
      throw new Error("This transfer is no longer active.");
    }

    const matched = data.computedSha256 === transfer.original_sha256;
    const metrics = { ...(transfer.metrics as Record<string, unknown>), ...data.metrics };

    if (!matched) {
      const threat = await raiseThreat(admin, {
        type: "INTEGRITY_FAILURE",
        userId,
        transferId: transfer.id,
        ip,
        details: { expected: transfer.original_sha256, computed: data.computedSha256 },
      });
      await logAudit(admin, {
        userId,
        transferId: transfer.id,
        event: "INTEGRITY_FAILED",
        severity: "critical",
        ip,
        action: "DOWNLOAD_BLOCKED",
      });
      return { ok: false as const, threat };
    }

    await admin
      .from("transfers")
      .update({ status: "COMPLETED", metrics: metrics as never })
      .eq("id", transfer.id);
    await logAudit(admin, {
      userId,
      transferId: transfer.id,
      event: "INTEGRITY_VERIFIED",
      ip,
      action: "HASH_MATCH",
    });
    await logAudit(admin, { userId, transferId: transfer.id, event: "DOWNLOAD_COMPLETED", ip });
    await logAudit(admin, { userId, transferId: transfer.id, event: "TRANSFER_COMPLETED", ip });
    await notify(
      admin,
      transfer.sender_id,
      transfer.id,
      "Transfer completed",
      "The recipient decrypted your file and SHA-256 integrity verification passed.",
    );
    return { ok: true as const };
  });

/** Faculty demonstration: routes simulated events through the real threat engine. */
export const simulateThreat = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => simulateSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, raiseThreat } = await import("./security.server");
    const admin = await getAdmin();
    if (data.transferId) {
      const { data: transfer } = await admin
        .from("transfers")
        .select("id, sender_id, recipient_id")
        .eq("id", data.transferId)
        .maybeSingle();
      if (
        !transfer ||
        (transfer.sender_id !== context.userId && transfer.recipient_id !== context.userId)
      )
        throw new Error("You can only simulate threats on your own transfers.");
    }
    return raiseThreat(admin, {
      type: data.type,
      userId: context.userId,
      transferId: data.transferId ?? null,
      ip: clientIp(),
      simulated: true,
      details: { source: "DEMO SIMULATION" },
    });
  });

/** Login rate limiting + failed login logging (callable before a session exists). */
export const recordLoginAttempt = createServerFn({ method: "POST" })
  .inputValidator((d: unknown) => loginAttemptSchema.parse(d))
  .handler(async ({ data }) => {
    const { getAdmin, logAudit } = await import("./security.server");
    const admin = await getAdmin();
    const ip = clientIp();
    const since = new Date(Date.now() - 15 * 60_000).toISOString();

    const { data: recent } = await admin
      .from("audit_logs")
      .select("id, metadata")
      .eq("event", "LOGIN_FAILED")
      .gte("created_at", since)
      .limit(200);
    const failures = (recent ?? []).filter(
      (row) => (row.metadata as { email?: string } | null)?.email === data.email,
    ).length;

    if (!data.success) {
      await logAudit(admin, {
        userId: null,
        event: "LOGIN_FAILED",
        severity: "medium",
        ip,
        action: "CREDENTIAL_REJECTED",
        metadata: { email: data.email },
      });
    }
    const locked = failures >= 5;
    if (locked)
      await logAudit(admin, {
        userId: null,
        event: "LOGIN_RATE_LIMITED",
        severity: "high",
        ip,
        action: "TEMPORARY_LOCKOUT",
        metadata: { email: data.email, failures },
      });
    return { locked, failures, windowMinutes: 15 };
  });

export const adminAction = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => adminActionSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin, logAudit, isAdmin } = await import("./security.server");
    const admin = await getAdmin();
    if (!(await isAdmin(admin, context.userId))) throw new Error("Administrator role required.");

    if (data.action === "REVOKE_SESSIONS") {
      await admin
        .from("app_sessions")
        .update({ revoked: true, revoked_reason: "ADMIN_REVOKED" })
        .eq("user_id", data.targetUserId)
        .eq("revoked", false);
    } else if (data.action === "SUSPEND_USER") {
      await admin.from("profiles").update({ status: "suspended" }).eq("id", data.targetUserId);
    } else if (data.action === "REINSTATE_USER") {
      await admin.from("profiles").update({ status: "active" }).eq("id", data.targetUserId);
    } else if (data.action === "RESET_TRUST") {
      await admin.from("profiles").update({ trust_score: 100 }).eq("id", data.targetUserId);
    } else if (data.action === "TERMINATE_TRANSFER" && data.transferId) {
      await admin
        .from("transfers")
        .update({ status: "TERMINATED", terminated_reason: "ADMIN_TERMINATED" })
        .eq("id", data.transferId);
    }

    await logAudit(admin, {
      userId: context.userId,
      transferId: data.transferId ?? null,
      event: `ADMIN_${data.action}`,
      severity: "high",
      ip: clientIp(),
      action: data.action,
      metadata: { targetUserId: data.targetUserId },
    });
    return { ok: true };
  });

/** Aggregated platform metrics for the administrator dashboard. */
export const adminOverview = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getAdmin, isAdmin } = await import("./security.server");
    const admin = await getAdmin();
    if (!(await isAdmin(admin, context.userId))) throw new Error("Administrator role required.");

    const [profiles, transfers, incidents, sessions] = await Promise.all([
      admin.from("profiles").select("id, email, full_name, trust_score, status, created_at"),
      admin.from("transfers").select("id, status, metrics, created_at, sender_id, recipient_id"),
      admin
        .from("threat_incidents")
        .select("id, threat_type, severity, blocked, simulated, created_at"),
      admin.from("app_sessions").select("id, user_id, revoked, expires_at"),
    ]);

    const rows = transfers.data ?? [];
    const avg = (key: string) => {
      const values = rows
        .map((t) => Number((t.metrics as Record<string, number> | null)?.[key] ?? 0))
        .filter((n) => n > 0);
      return values.length ? Math.round(values.reduce((a, b) => a + b, 0) / values.length) : 0;
    };

    return {
      users: profiles.data ?? [],
      transfers: rows,
      incidents: incidents.data ?? [],
      activeSessions: (sessions.data ?? []).filter(
        (s) => !s.revoked && new Date(s.expires_at).getTime() > Date.now(),
      ).length,
      averages: {
        encryptionMs: avg("encryptionMs"),
        hashingMs: avg("hashingMs"),
        transferMs: avg("uploadMs"),
        verificationMs: avg("verificationMs"),
      },
    };
  });

/**
 * Security Digital Twin real-time state.
 * Returns comprehensive live topology: user nodes, transfers with geospatial coordinates,
 * cryptographic telemetry, active security events, trust history, and SOC summary counters.
 */
export const getDigitalTwinState = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getAdmin } = await import("./security.server");
    const admin = await getAdmin();

    const [
      profilesRes,
      transfersRes,
      fileMetadataRes,
      transferKeysRes,
      securityEventsRes,
      threatIncidentsRes,
      trustEventsRes,
      sessionsRes,
      devicesRes,
    ] = await Promise.all([
      admin
        .from("profiles")
        .select("id, email, full_name, trust_score, trust_status, status, created_at, updated_at")
        .order("created_at", { ascending: false }),
      admin
        .from("transfers")
        .select(
          "id, sender_id, recipient_id, status, security_level, storage_path, iv, original_sha256, ciphertext_sha256, sender_latitude, sender_longitude, sender_location_timestamp, receiver_latitude, receiver_longitude, receiver_location_timestamp, created_at, expires_at, metrics, download_count, max_downloads, terminated_reason",
        )
        .order("created_at", { ascending: false })
        .limit(100),
      admin
        .from("file_metadata")
        .select("transfer_id, original_name, size_bytes, mime_type, extension, hash_algorithm"),
      admin.from("transfer_keys").select("transfer_id, wrap_algorithm"),
      admin
        .from("security_events")
        .select(
          "id, user_id, transfer_id, event_type, severity, ip_address, trust_delta, simulated, metadata, created_at",
        )
        .order("created_at", { ascending: false })
        .limit(60),
      admin
        .from("threat_incidents")
        .select(
          "id, user_id, transfer_id, threat_type, severity, action_taken, trust_delta, blocked, simulated, resolved, details, created_at",
        )
        .order("created_at", { ascending: false })
        .limit(60),
      admin
        .from("trust_events")
        .select(
          "id, user_id, security_event_id, previous_score, delta, new_score, reason, created_at",
        )
        .order("created_at", { ascending: false })
        .limit(60),
      admin
        .from("app_sessions")
        .select("id, user_id, device_fingerprint, ip_address, revoked, expires_at, last_active")
        .order("last_active", { ascending: false })
        .limit(100),
      admin
        .from("devices")
        .select("id, user_id, fingerprint, trusted, last_seen")
        .order("last_seen", { ascending: false })
        .limit(100),
    ]);

    const profiles = profilesRes.data ?? [];
    const transfers = transfersRes.data ?? [];
    const fileMetaMap = new Map((fileMetadataRes.data ?? []).map((f) => [f.transfer_id, f]));
    const keyMap = new Map((transferKeysRes.data ?? []).map((k) => [k.transfer_id, k]));
    const profileMap = new Map(profiles.map((p) => [p.id, p]));
    const sessions = sessionsRes.data ?? [];
    const devices = devicesRes.data ?? [];
    const nowIso = new Date().toISOString();

    const activeSessionsByUser = new Map<string, number>();
    for (const s of sessions) {
      if (!s.revoked && new Date(s.expires_at).getTime() > Date.now()) {
        activeSessionsByUser.set(s.user_id, (activeSessionsByUser.get(s.user_id) ?? 0) + 1);
      }
    }

    const devicesByUser = new Map<string, number>();
    for (const d of devices) {
      devicesByUser.set(d.user_id, (devicesByUser.get(d.user_id) ?? 0) + 1);
    }

    const userNodes = profiles.map((p) => {
      const score = p.trust_score ?? 100;
      let band: "TRUSTED" | "NORMAL" | "CAUTION" | "HIGH RISK" = "HIGH RISK";
      if (score >= 90) band = "TRUSTED";
      else if (score >= 75) band = "NORMAL";
      else if (score >= 60) band = "CAUTION";

      return {
        id: p.id,
        email: p.email,
        fullName: p.full_name ?? p.email.split("@")[0],
        trustScore: score,
        trustStatus: band,
        accountStatus: p.status,
        activeSessions: activeSessionsByUser.get(p.id) ?? 0,
        deviceCount: devicesByUser.get(p.id) ?? 0,
        createdAt: p.created_at,
        updatedAt: p.updated_at,
      };
    });

    const transferObjects = transfers.map((t) => {
      const meta = fileMetaMap.get(t.id);
      const keyInfo = keyMap.get(t.id);
      const sender = profileMap.get(t.sender_id);
      const recipient = profileMap.get(t.recipient_id);

      const senderScore = sender?.trust_score ?? 100;
      const recipientScore = recipient?.trust_score ?? 100;

      return {
        id: t.id,
        senderId: t.sender_id,
        senderName: sender?.full_name ?? sender?.email ?? "Unknown Sender",
        senderEmail: sender?.email ?? "unknown@system",
        senderTrustScore: senderScore,
        recipientId: t.recipient_id,
        recipientName: recipient?.full_name ?? recipient?.email ?? "Unknown Recipient",
        recipientEmail: recipient?.email ?? "unknown@system",
        recipientTrustScore: recipientScore,
        fileName: meta?.original_name ?? "encrypted-payload.bin",
        fileSizeBytes: meta?.size_bytes ?? 0,
        mimeType: meta?.mime_type ?? "application/octet-stream",
        encryptionAlgorithm: "AES-256-GCM",
        keyWrapAlgorithm: keyInfo?.wrap_algorithm ?? "RSA-OAEP-2048",
        hashAlgorithm: meta?.hash_algorithm ?? "SHA-256",
        originalSha256: t.original_sha256,
        ciphertextSha256: t.ciphertext_sha256,
        status: t.status,
        securityLevel: t.security_level,
        senderLatitude: t.sender_latitude,
        senderLongitude: t.sender_longitude,
        senderLocationTimestamp: t.sender_location_timestamp,
        receiverLatitude: t.receiver_latitude,
        receiverLongitude: t.receiver_longitude,
        receiverLocationTimestamp: t.receiver_location_timestamp,
        hasLocation: Boolean(t.sender_latitude != null || t.receiver_latitude != null),
        downloadCount: t.download_count,
        maxDownloads: t.max_downloads,
        createdAt: t.created_at,
        expiresAt: t.expires_at,
        terminatedReason: t.terminated_reason,
        metrics: (t.metrics as Record<string, number> | null) ?? {},
      };
    });

    const activeTransfers = transfers.filter(
      (t) => !["TERMINATED", "COMPLETED", "EXPIRED", "FAILED"].includes(t.status),
    ).length;

    const securityEvents = (securityEventsRes.data ?? []).map((e) => {
      const user = profileMap.get(e.user_id ?? "");
      return {
        id: e.id,
        userId: e.user_id,
        userEmail: user?.email ?? "System Event",
        transferId: e.transfer_id,
        eventType: e.event_type,
        severity: e.severity,
        ipAddress: e.ip_address,
        trustDelta: e.trust_delta,
        simulated: e.simulated,
        metadata: (e.metadata && typeof e.metadata === "object" ? e.metadata : {}) as Record<
          string,
          string | number | boolean | null
        >,
        createdAt: e.created_at,
      };
    });

    const threatIncidents = (threatIncidentsRes.data ?? []).map((i) => {
      const user = profileMap.get(i.user_id ?? "");
      return {
        id: i.id,
        userId: i.user_id,
        userName: user?.full_name ?? user?.email ?? "Unknown Account",
        transferId: i.transfer_id,
        threatType: i.threat_type,
        severity: i.severity,
        actionTaken: i.action_taken,
        trustDelta: i.trust_delta,
        blocked: i.blocked,
        simulated: i.simulated,
        resolved: i.resolved,
        details: (i.details && typeof i.details === "object" ? i.details : {}) as Record<
          string,
          string | number | boolean | null
        >,
        createdAt: i.created_at,
      };
    });

    const trustEvents = (trustEventsRes.data ?? []).map((te) => {
      const user = profileMap.get(te.user_id);
      return {
        id: te.id,
        userId: te.user_id,
        userName: user?.full_name ?? user?.email ?? "User",
        userEmail: user?.email ?? "",
        securityEventId: te.security_event_id,
        previousScore: te.previous_score,
        delta: te.delta,
        newScore: te.new_score,
        reason: te.reason,
        createdAt: te.created_at,
      };
    });

    const openIncidents = threatIncidents.filter((i) => !i.resolved).length;
    const blockedCount =
      transfers.filter((t) => t.status === "TERMINATED").length +
      threatIncidents.filter((i) => i.blocked).length;

    return {
      summary: {
        activeUsers: profiles.filter((p) => p.status === "active").length,
        totalUsers: profiles.length,
        activeTransfers,
        totalTransfers: transfers.length,
        trustedUsers: userNodes.filter((u) => u.trustScore >= 90).length,
        normalUsers: userNodes.filter((u) => u.trustScore >= 75 && u.trustScore < 90).length,
        cautionUsers: userNodes.filter((u) => u.trustScore >= 60 && u.trustScore < 75).length,
        highRiskUsers: userNodes.filter((u) => u.trustScore < 60).length,
        activeThreats: openIncidents,
        blockedTransfers: blockedCount,
        integrityFailures: securityEvents.filter((e) => e.eventType === "INTEGRITY_FAILURE").length,
        tokenReplays: securityEvents.filter((e) => e.eventType === "TOKEN_REPLAY").length,
        unauthorizedAttempts: securityEvents.filter((e) => e.eventType === "UNAUTHORIZED_RECEIVER")
          .length,
      },
      userNodes,
      transferObjects,
      securityEvents,
      threatIncidents,
      trustEvents,
      currentUserId: context.userId,
      timestamp: nowIso,
    };
  });
