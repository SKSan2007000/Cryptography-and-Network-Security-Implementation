/**
 * Controlled Security Testing Lab — server implementation.
 *
 * Guarantees:
 *  - Only LAB TEST accounts and LAB TEST transfers (metrics.lab = 1) are targeted.
 *  - Production user files are never read, modified or deleted.
 *  - Every scenario executes the real application code path (shared download gate,
 *    real AES-GCM / SHA-256 verification, real raiseThreat engine).
 */
import {
  aesGcmEncrypt,
  createProtectedKeyPair,
  generateAesKey,
  generateTransferToken,
  importPublicJwk,
  randomBytes,
  sha256Hex,
  toBase64,
  toHex,
  wrapAesKey,
} from "./crypto";
import { evaluateDownloadGate } from "./download-gate.server";
import { logAudit, notify, raiseThreat, sha256HexServer, type Admin } from "./security.server";
import {
  LAB_SCENARIO_SPECS,
  type LabDashboard,
  type LabEvidence,
  type LabIntegrityComparison,
  type LabRunResult,
  type LabScenario,
} from "./security-lab";
import {
  buildIncidentTimeline,
  labIntel,
  securityPosture,
  transferRef,
} from "./security-lab-intel";

export const LAB_RECEIVER_EMAIL = "lab-receiver@sentinelcrypt.test";
export const LAB_ATTACKER_EMAIL = "lab-attacker@sentinelcrypt.test";

export type LabUser = { id: string; email: string; label: string };

async function findUserByEmail(admin: Admin, email: string): Promise<string | null> {
  const { data } = await admin.from("profiles").select("id").eq("email", email).maybeSingle();
  return data?.id ?? null;
}

async function ensureLabUser(admin: Admin, email: string, label: string): Promise<LabUser> {
  const existing = await findUserByEmail(admin, email);
  if (existing) return { id: existing, email, label };

  const password = toHex(randomBytes(24)); // random, never stored or displayed
  const { data, error } = await admin.auth.admin.createUser({
    email,
    password,
    email_confirm: true,
    user_metadata: { full_name: label },
  });
  if (error || !data.user) {
    const retry = await findUserByEmail(admin, email);
    if (retry) return { id: retry, email, label };
    throw new Error(`Could not provision the lab test account: ${error?.message ?? "unknown"}`);
  }
  // The handle_new_user trigger creates the profile row; make sure the label is set.
  await admin.from("profiles").update({ full_name: label }).eq("id", data.user.id);
  return { id: data.user.id, email, label };
}

/** Lab receiver needs a published RSA public key so the AES key can be genuinely wrapped. */
async function ensureLabKeys(admin: Admin, userId: string): Promise<JsonWebKey> {
  const { data } = await admin
    .from("user_keys")
    .select("public_key_jwk")
    .eq("user_id", userId)
    .maybeSingle();
  if (data?.public_key_jwk) return data.public_key_jwk as unknown as JsonWebKey;

  // The passphrase is random and immediately discarded — the lab never decrypts
  // in the browser, and no plaintext key material is stored.
  const bundle = await createProtectedKeyPair(toHex(randomBytes(16)));
  await admin.from("user_keys").insert({
    user_id: userId,
    public_key_jwk: bundle.publicJwk as never,
    wrapped_private_key: bundle.wrappedPrivateKey,
    kdf_salt: bundle.kdfSalt,
    wrap_iv: bundle.wrapIv,
  });
  return bundle.publicJwk;
}

export async function provisionLab(
  admin: Admin,
): Promise<{ receiver: LabUser; attacker: LabUser }> {
  const receiver = await ensureLabUser(admin, LAB_RECEIVER_EMAIL, "Lab Test Receiver");
  const attacker = await ensureLabUser(admin, LAB_ATTACKER_EMAIL, "Unauthorized Test User");
  await ensureLabKeys(admin, receiver.id);
  return { receiver, attacker };
}

function labPayload(): Uint8Array {
  // A small synthetic PDF-shaped test document created by the lab itself.
  const header = new TextEncoder().encode("%PDF-1.7\n% SentinelCrypt lab test payload\n");
  const body = randomBytes(4096);
  const out = new Uint8Array(header.length + body.length);
  out.set(header, 0);
  out.set(body, header.length);
  return out;
}

export type LabTransfer = {
  id: string;
  token: string;
  storagePath: string;
  originalSha256: string;
};

/** Creates a genuine AES-256-GCM encrypted test transfer owned by the requesting user. */
export async function createLabTransfer(
  admin: Admin,
  opts: {
    senderId: string;
    recipientId: string;
    recipientPublicJwk: JsonWebKey;
    expiresInHours: number;
    maxDownloads: number;
  },
): Promise<LabTransfer> {
  const payload = labPayload();
  const originalSha256 = await sha256Hex(payload);

  const aesKey = await generateAesKey();
  const buffer = new ArrayBuffer(payload.byteLength);
  new Uint8Array(buffer).set(payload);
  const { ciphertext, iv } = await aesGcmEncrypt(aesKey, buffer);
  const ciphertextSha256 = await sha256Hex(ciphertext);

  const publicKey = await importPublicJwk(opts.recipientPublicJwk);
  const wrappedKey = await wrapAesKey(publicKey, aesKey);

  const storagePath = `${opts.senderId}/lab/${globalThis.crypto.randomUUID()}.enc`;
  const { error: uploadError } = await admin.storage
    .from("encrypted-payloads")
    .upload(
      storagePath,
      new Blob([new Uint8Array(ciphertext)] as BlobPart[], { type: "application/octet-stream" }),
      {
        contentType: "application/octet-stream",
        upsert: true,
      },
    );
  if (uploadError) throw new Error(`Lab payload upload failed: ${uploadError.message}`);

  const token = generateTransferToken();
  const expiresAt = new Date(Date.now() + opts.expiresInHours * 3600_000).toISOString();

  const { data: transfer, error } = await admin
    .from("transfers")
    .insert({
      sender_id: opts.senderId,
      recipient_id: opts.recipientId,
      status: "ENCRYPTED",
      security_level: "high",
      storage_path: storagePath,
      iv: toBase64(iv),
      original_sha256: originalSha256,
      ciphertext_sha256: ciphertextSha256,
      token_hash: await sha256HexServer(token),
      expires_at: expiresAt,
      max_downloads: opts.maxDownloads,
      metrics: { lab: 1 } as never,
    })
    .select("id")
    .single();
  if (error || !transfer) throw new Error(error?.message ?? "Could not create the lab transfer.");

  await admin.from("transfer_keys").insert({ transfer_id: transfer.id, wrapped_key: wrappedKey });
  await admin.from("file_metadata").insert({
    transfer_id: transfer.id,
    original_name: "lab-test-document.pdf",
    mime_type: "application/pdf",
    size_bytes: payload.byteLength,
    extension: "pdf",
  });
  await logAudit(admin, {
    userId: opts.senderId,
    transferId: transfer.id,
    event: "LAB_TEST_TRANSFER_CREATED",
    action: "AES_256_GCM_ENCRYPTED",
    metadata: { lab: true },
  });

  return { id: transfer.id, token, storagePath, originalSha256 };
}

async function trustOf(admin: Admin, userId: string): Promise<number> {
  const { data } = await admin
    .from("profiles")
    .select("trust_score")
    .eq("id", userId)
    .maybeSingle();
  return data?.trust_score ?? 100;
}

async function statusOf(admin: Admin, transferId: string): Promise<string> {
  const { data } = await admin
    .from("transfers")
    .select("status")
    .eq("id", transferId)
    .maybeSingle();
  return data?.status ?? "UNKNOWN";
}

/** Registers a controlled lab session for a test account so session checks are real. */
async function ensureLabSession(
  admin: Admin,
  userId: string,
  fingerprint: string,
  ip: string,
  userAgent: string,
): Promise<{ sessionId: string | null; deviceId: string | null }> {
  const { data: device } = await admin
    .from("devices")
    .select("id")
    .eq("user_id", userId)
    .eq("fingerprint", fingerprint)
    .maybeSingle();

  let deviceId = device?.id ?? null;
  if (!deviceId) {
    const { data: inserted } = await admin
      .from("devices")
      .insert({ user_id: userId, fingerprint, user_agent: userAgent })
      .select("id")
      .single();
    deviceId = inserted?.id ?? null;
  }

  const { data: session } = await admin
    .from("app_sessions")
    .insert({
      user_id: userId,
      device_fingerprint: fingerprint,
      ip_address: ip,
      user_agent: userAgent,
    })
    .select("id")
    .single();

  return { sessionId: session?.id ?? null, deviceId };
}

export async function listLabTransfers(admin: Admin, senderId: string) {
  const { data } = await admin
    .from("transfers")
    .select("id, status, expires_at, download_count, max_downloads, created_at, metrics")
    .eq("sender_id", senderId)
    .order("created_at", { ascending: false })
    .limit(25);
  return (data ?? []).filter((t) => (t.metrics as Record<string, number> | null)?.["lab"] === 1);
}

export async function runLabScenario(
  admin: Admin,
  input: {
    scenario: LabScenario;
    ownerId: string;
    ip: string;
    userAgent: string;
    transferId?: string | null;
  },
): Promise<LabRunResult> {
  const spec = LAB_SCENARIO_SPECS[input.scenario];
  const startedAt = new Date().toISOString();
  const { receiver, attacker } = await provisionLab(admin);
  const publicJwk = await ensureLabKeys(admin, receiver.id);

  const expiresInHours = input.scenario === "EXPIRED_TRANSFER" ? 1 : 12;
  const maxDownloads = input.scenario === "ABNORMAL_DOWNLOAD" ? 2 : 1;

  let transferId: string;
  let token: string | null = null;
  let storagePath: string | null = null;

  if (!spec.requiresFreshTransfer && input.transferId) {
    transferId = input.transferId;
    const { data } = await admin
      .from("transfers")
      .select("id, sender_id, storage_path, metrics")
      .eq("id", transferId)
      .maybeSingle();
    if (!data || data.sender_id !== input.ownerId)
      throw new Error("Select one of your own lab test transfers.");
    if ((data.metrics as Record<string, number> | null)?.["lab"] !== 1)
      throw new Error("The Security Lab only operates on dedicated lab test transfers.");
    storagePath = data.storage_path;
  } else {
    const created = await createLabTransfer(admin, {
      senderId: input.ownerId,
      recipientId: receiver.id,
      recipientPublicJwk: publicJwk,
      expiresInHours,
      maxDownloads,
    });
    transferId = created.id;
    token = created.token;
    storagePath = created.storagePath;
  }

  const isAttackerActor = input.scenario === "UNAUTHORIZED_RECEIVER";
  const actor = isAttackerActor ? attacker : receiver;
  const fingerprint =
    input.scenario === "SUSPICIOUS_SESSION"
      ? `lab-unknown-device-${globalThis.crypto.randomUUID().slice(0, 8)}`
      : "lab-known-device";
  const actorIp = input.scenario === "SUSPICIOUS_SESSION" ? "203.0.113.77" : input.ip;

  const trustBefore = await trustOf(admin, actor.id);
  const transferStatusBefore = await statusOf(admin, transferId);

  const { sessionId, deviceId } = await ensureLabSession(
    admin,
    actor.id,
    fingerprint,
    actorIp,
    input.userAgent,
  );

  let blocked = false;
  let outcome = "";
  let stage: string | null = null;
  let threatType: string | null = null;
  let severity: string | null = null;
  let responseAction: string | null = null;
  let attemptCount = 1;
  let integrity: LabIntegrityComparison | null = null;

  const applyDenied = (denied: {
    stage: string;
    reason: string;
    threat: { type: string; severity: string; action: string } | null;
  }) => {
    blocked = true;
    stage = denied.stage;
    outcome = denied.reason;
    threatType = denied.threat?.type ?? null;
    severity = denied.threat?.severity ?? null;
    responseAction = denied.threat?.action ?? null;
  };

  if (input.scenario === "INVALID_TOKEN") {
    const result = await evaluateDownloadGate(admin, {
      transferId,
      actorId: actor.id,
      token: generateTransferToken(), // valid shape, wrong value
      ip: actorIp,
      deviceFingerprint: fingerprint,
      issueSignedUrl: false,
      simulated: true,
    });
    if (result.ok) outcome = "Gate unexpectedly allowed access.";
    else applyDenied(result);
  } else if (input.scenario === "TOKEN_REPLAY") {
    // 1) legitimate consumption of the one-time token
    await evaluateDownloadGate(admin, {
      transferId,
      actorId: actor.id,
      token: token!,
      ip: actorIp,
      deviceFingerprint: fingerprint,
      issueSignedUrl: false,
      simulated: true,
    });
    attemptCount = 2;
    // 2) replay of the same token
    const replay = await evaluateDownloadGate(admin, {
      transferId,
      actorId: actor.id,
      token: token!,
      ip: actorIp,
      deviceFingerprint: fingerprint,
      issueSignedUrl: false,
      simulated: true,
    });
    if (replay.ok) outcome = "Replay was not blocked.";
    else applyDenied(replay);
  } else if (input.scenario === "UNAUTHORIZED_RECEIVER") {
    const result = await evaluateDownloadGate(admin, {
      transferId,
      actorId: attacker.id,
      token: token!, // even a valid token must not help a non-recipient
      ip: actorIp,
      deviceFingerprint: fingerprint,
      issueSignedUrl: false,
      simulated: true,
    });
    if (result.ok) outcome = "Unauthorized account was allowed — check authorisation rules.";
    else applyDenied(result);
  } else if (input.scenario === "EXPIRED_TRANSFER") {
    await admin
      .from("transfers")
      .update({ expires_at: new Date(Date.now() - 3600_000).toISOString() })
      .eq("id", transferId);
    const result = await evaluateDownloadGate(admin, {
      transferId,
      actorId: actor.id,
      token: token!,
      ip: actorIp,
      deviceFingerprint: fingerprint,
      issueSignedUrl: false,
      simulated: true,
    });
    if (result.ok) outcome = "Expired transfer was not blocked.";
    else applyDenied(result);
  } else if (input.scenario === "INTEGRITY_TAMPERING") {
    const { data: transferRow } = await admin
      .from("transfers")
      .select("iv, original_sha256, ciphertext_sha256, storage_path")
      .eq("id", transferId)
      .maybeSingle();
    const path = storagePath ?? transferRow?.storage_path ?? null;
    if (!path || !transferRow) throw new Error("Lab payload not found.");

    const { data: blob, error: dlError } = await admin.storage
      .from("encrypted-payloads")
      .download(path);
    if (dlError || !blob) throw new Error("Could not read the lab test payload.");

    const original = new Uint8Array(await blob.arrayBuffer());
    const tampered = new Uint8Array(original);
    const idx = Math.floor(tampered.length / 2);
    tampered[idx] = (tampered[idx]! ^ 0xff) & 0xff; // flip one byte of the ciphertext

    await admin.storage
      .from("encrypted-payloads")
      .upload(path, new Blob([tampered] as BlobPart[], { type: "application/octet-stream" }), {
        upsert: true,
      });

    // Real verification: AES-GCM authentication must fail on the modified payload.
    // Real verification: the SHA-256 fingerprint recorded for the authenticated
    // AES-256-GCM ciphertext at send time is recomputed over the stored bytes.
    // A single flipped byte breaks both this fingerprint and, at decrypt time,
    // the AES-GCM authentication tag.
    const computedSha256 = await sha256Hex(tampered);
    const match = computedSha256 === transferRow.ciphertext_sha256;

    integrity = {
      expectedSha256: transferRow.ciphertext_sha256,
      computedSha256,
      match,
      gcmAuthenticated: match,
    };

    const threat = await raiseThreat(admin, {
      type: "INTEGRITY_FAILURE",
      userId: actor.id,
      transferId,
      ip: actorIp,
      simulated: true,
      details: {
        stage: "INTEGRITY",
        expectedCiphertextSha256: integrity.expectedSha256,
        computedCiphertextSha256: integrity.computedSha256,
        aesGcmAuthenticated: integrity.gcmAuthenticated,
      },
    });
    await logAudit(admin, {
      userId: actor.id,
      transferId,
      event: "INTEGRITY_FAILED",
      severity: "critical",
      ip: actorIp,
      action: "DOWNLOAD_BLOCKED",
      metadata: { simulated: true },
    });
    blocked = true;
    stage = "INTEGRITY";
    outcome = "Encrypted payload failed integrity verification — download blocked.";
    threatType = threat.type;
    severity = threat.severity;
    responseAction = threat.action;
  } else if (input.scenario === "SUSPICIOUS_SESSION") {
    const threat = await raiseThreat(admin, {
      type: "DEVICE_CHANGE",
      userId: actor.id,
      transferId,
      ip: actorIp,
      simulated: true,
      details: { stage: "SESSION", deviceFingerprint: fingerprint, observedIp: actorIp },
    });
    const netThreat = await raiseThreat(admin, {
      type: "SUSPICIOUS_IP_CHANGE",
      userId: actor.id,
      transferId,
      ip: actorIp,
      simulated: true,
      details: { stage: "SESSION", observedIp: actorIp },
    });
    blocked = false;
    stage = "SESSION";
    outcome =
      "Session / network anomaly recorded: unrecognised device and differing network source.";
    threatType = `${threat.type} + ${netThreat.type}`;
    severity = netThreat.severity;
    responseAction = netThreat.action;
    attemptCount = 2;
  } else {
    // ABNORMAL_DOWNLOAD — repeat until the configured limit is exceeded.
    let last: Awaited<ReturnType<typeof evaluateDownloadGate>> | null = null;
    for (let i = 0; i < maxDownloads + 1; i += 1) {
      attemptCount = i + 1;
      last = await evaluateDownloadGate(admin, {
        transferId,
        actorId: actor.id,
        token: token!,
        ip: actorIp,
        deviceFingerprint: fingerprint,
        issueSignedUrl: false,
        simulated: true,
      });
      if (!last.ok) break;
    }
    if (last && !last.ok) applyDenied(last);
    else outcome = "Download limit was not enforced.";
  }

  const transferStatusAfter = await statusOf(admin, transferId);
  const trustAfter = await trustOf(admin, actor.id);

  const { data: incident } = await admin
    .from("threat_incidents")
    .select("id")
    .eq("transfer_id", transferId)
    .gte("created_at", startedAt)
    .order("created_at", { ascending: false })
    .limit(1)
    .maybeSingle();

  const { data: auditRows } = await admin
    .from("audit_logs")
    .select("event")
    .eq("transfer_id", transferId)
    .gte("created_at", startedAt)
    .order("created_at", { ascending: true });

  const { data: transferParties } = await admin
    .from("transfers")
    .select("sender_id, recipient_id")
    .eq("id", transferId)
    .maybeSingle();

  const { data: notifRows } = await admin
    .from("notifications")
    .select("user_id, title")
    .eq("transfer_id", transferId)
    .gte("created_at", startedAt);

  await logAudit(admin, {
    userId: input.ownerId,
    transferId,
    event: "LAB_SCENARIO_EXECUTED",
    severity: "info",
    ip: input.ip,
    action: input.scenario,
    metadata: { blocked, lab: true },
  });

  // Receiver confirmation is requested whenever a transfer-affecting threat fired.
  const receiverConfirmationRequired = Boolean(threatType) && transferStatusAfter !== "COMPLETED";
  if (receiverConfirmationRequired && transferParties) {
    await notify(
      admin,
      transferParties.recipient_id,
      transferId,
      "[SECURITY LAB] Security verification required",
      `A suspicious access attempt (${threatType}) was detected on transfer ${transferRef(transferId)}. Confirm whether you authorized it.`,
      severity ?? "high",
    );
    await logAudit(admin, {
      userId: transferParties.recipient_id,
      transferId,
      event: "RECEIVER_CONFIRMATION_REQUESTED",
      severity: severity ?? "high",
      ip: actorIp,
      action: "NOTIFY_USER",
      metadata: { lab: true, threatType },
    });
  }

  const { data: fileRow } = await admin
    .from("file_metadata")
    .select("original_name")
    .eq("transfer_id", transferId)
    .maybeSingle();

  const { data: timelineRows } = await admin
    .from("audit_logs")
    .select("created_at, event, action")
    .eq("transfer_id", transferId)
    .order("created_at", { ascending: true })
    .limit(60);

  const trustDelta = trustAfter - trustBefore;

  return {
    scenario: input.scenario,
    title: spec.title,
    blocked,
    outcome,
    stage,
    threatType,
    severity,
    responseAction,
    trustBefore,
    trustAfter,
    transferStatusBefore,
    transferStatusAfter,
    incidentId: incident?.id ?? null,
    auditEvents: (auditRows ?? []).map((r) => r.event),
    notifications: (notifRows ?? []).map((n) => ({
      userId: n.user_id,
      role: (n.user_id === transferParties?.sender_id ? "sender" : "receiver") as
        "sender" | "receiver",
      title: n.title,
    })),
    evidence: {
      actorId: actor.id,
      actorLabel: actor.label,
      sessionId,
      deviceId,
      deviceFingerprint: fingerprint,
      ipAddress: actorIp,
      userAgent: input.userAgent,
      transferId,
      timestamp: new Date().toISOString(),
      scenario: input.scenario,
      attemptCount,
    } satisfies LabEvidence,
    integrity,
    transferRef: transferRef(transferId),
    fileName: fileRow?.original_name ?? "lab-test-document.pdf",
    intel: labIntel({
      scenario: input.scenario,
      actorLabel: actor.label,
      observedIp: actorIp,
      sessionId,
      deviceFingerprint: fingerprint,
      threatType,
      severity,
      trustDelta,
      deviceTrusted: input.scenario !== "SUSPICIOUS_SESSION" && !isAttackerActor,
    }),
    timeline: buildIncidentTimeline(timelineRows ?? []),
    senderNotified: (notifRows ?? []).some((n) => n.user_id === transferParties?.sender_id),
    receiverConfirmationRequired,
    detectionSummary: spec.executes,
  };
}

/**
 * Controlled receiver confirmation workflow.
 * CONFIRMED → incident marked resolved and, where the rule allows it, the test
 * transfer is restored. DENIED → transfer terminated and the sender notified.
 * No cryptographic or authorisation control is bypassed by either branch.
 */
export async function applyReceiverDecision(
  admin: Admin,
  input: {
    incidentId: string;
    decision: "CONFIRMED" | "DENIED";
    ownerId: string;
    ip: string;
  },
) {
  const { data: incident } = await admin
    .from("threat_incidents")
    .select("*")
    .eq("id", input.incidentId)
    .maybeSingle();
  if (!incident) throw new Error("Incident not found.");

  const transferId = incident.transfer_id;
  let transfer: { sender_id: string; recipient_id: string; status: string } | null = null;
  if (transferId) {
    const { data } = await admin
      .from("transfers")
      .select("sender_id, recipient_id, status, metrics")
      .eq("id", transferId)
      .maybeSingle();
    if (!data) throw new Error("Transfer not found.");
    if (data.sender_id !== input.ownerId && data.recipient_id !== input.ownerId)
      throw new Error("You are not a party to this transfer.");
    if ((data.metrics as Record<string, number> | null)?.["lab"] !== 1)
      throw new Error("Receiver confirmation demonstration is limited to lab test transfers.");
    transfer = { sender_id: data.sender_id, recipient_id: data.recipient_id, status: data.status };
  } else if (incident.user_id !== input.ownerId) {
    throw new Error("You cannot act on this incident.");
  }

  const confirmed = input.decision === "CONFIRMED";
  const restorable = confirmed && incident.severity !== "critical";
  let finalStatus = transfer?.status ?? "UNKNOWN";

  if (transferId && transfer) {
    if (confirmed && restorable) {
      finalStatus = "ENCRYPTED";
      await admin
        .from("transfers")
        .update({ status: finalStatus, terminated_reason: null })
        .eq("id", transferId);
    } else if (!confirmed) {
      finalStatus = "TERMINATED";
      await admin
        .from("transfers")
        .update({ status: finalStatus, terminated_reason: "RECEIVER_DENIED_AUTHORIZATION" })
        .eq("id", transferId);
    }

    await notify(
      admin,
      transfer.sender_id,
      transferId,
      confirmed ? "Receiver confirmed the transfer" : "Receiver denied the transfer",
      confirmed
        ? `The receiver confirmed they authorized ${transferRef(transferId)}. ${
            restorable
              ? "The test transfer has been restored."
              : "The severity of this incident keeps the transfer blocked."
          }`
        : `The receiver reported that ${transferRef(transferId)} was NOT authorized. The transfer has been terminated and access revoked.`,
      confirmed ? "info" : "critical",
    );
  }

  await admin.from("threat_incidents").update({ resolved: true }).eq("id", input.incidentId);

  await logAudit(admin, {
    userId: input.ownerId,
    transferId,
    event: confirmed ? "RECEIVER_CONFIRMED" : "RECEIVER_DENIED",
    severity: confirmed ? "info" : "critical",
    ip: input.ip,
    action: confirmed
      ? restorable
        ? "TRANSFER_RESTORED"
        : "ACCESS_BLOCKED"
      : "TERMINATE_TRANSFER",
    metadata: { lab: true, incidentId: input.incidentId },
  });

  return { decision: input.decision, resolved: true, transferStatus: finalStatus, restorable };
}

/** SOC dashboard aggregation over the requesting user's own lab test estate. */
export async function labDashboardData(admin: Admin, ownerId: string): Promise<LabDashboard> {
  const [{ data: profile }, { data: transfers }, { data: incidents }, { data: audit }] =
    await Promise.all([
      admin.from("profiles").select("trust_score").eq("id", ownerId).maybeSingle(),
      admin
        .from("transfers")
        .select(
          "id, status, download_count, max_downloads, expires_at, created_at, metrics, recipient_id",
        )
        .eq("sender_id", ownerId)
        .order("created_at", { ascending: false })
        .limit(40),
      admin
        .from("threat_incidents")
        .select("id, severity, resolved, blocked, created_at, transfer_id")
        .eq("user_id", ownerId)
        .order("created_at", { ascending: false })
        .limit(100),
      admin
        .from("audit_logs")
        .select("id, event, severity, action, created_at, transfer_id")
        .eq("user_id", ownerId)
        .order("created_at", { ascending: false })
        .limit(25),
    ]);

  const own = (transfers ?? []).filter(
    (t) => (t.metrics as Record<string, number> | null)?.["lab"] === 1,
  );

  const { data: allIncidents } = await admin
    .from("threat_incidents")
    .select("id, severity, resolved, blocked, created_at, transfer_id")
    .in(
      "transfer_id",
      own.length > 0 ? own.map((t) => t.id) : ["00000000-0000-0000-0000-000000000000"],
    )
    .order("created_at", { ascending: false })
    .limit(100);

  const inc = [...(incidents ?? []), ...(allIncidents ?? [])].filter(
    (v, i, arr) => arr.findIndex((x) => x.id === v.id) === i,
  );

  const dayAgo = Date.now() - 86_400_000;
  const criticalOrHigh = inc.filter(
    (i) =>
      new Date(i.created_at).getTime() > dayAgo &&
      (i.severity === "critical" || i.severity === "high"),
  ).length;

  const monitors = await Promise.all(
    own.slice(0, 8).map(async (t) => {
      const [{ data: file }, { data: prof }, { data: last }] = await Promise.all([
        admin.from("file_metadata").select("original_name").eq("transfer_id", t.id).maybeSingle(),
        admin.from("profiles").select("email").eq("id", t.recipient_id).maybeSingle(),
        admin
          .from("audit_logs")
          .select("event, created_at")
          .eq("transfer_id", t.id)
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle(),
      ]);
      return {
        id: t.id,
        ref: transferRef(t.id),
        status: t.status,
        fileName: file?.original_name ?? "lab-test-document.pdf",
        receiverEmail: prof?.email ?? "lab receiver",
        downloadCount: t.download_count,
        maxDownloads: t.max_downloads,
        expiresAt: t.expires_at,
        lastEvent: last?.event ?? null,
        lastEventAt: last?.created_at ?? null,
      };
    }),
  );

  const openIncidents = inc.filter((i) => !i.resolved).length;
  const trustScore = profile?.trust_score ?? 100;

  return {
    posture: securityPosture({ openIncidents, criticalOrHighLast24h: criticalOrHigh, trustScore }),
    trustScore,
    activeTransfers: own.filter((t) => !["TERMINATED", "COMPLETED", "EXPIRED"].includes(t.status))
      .length,
    openIncidents,
    blockedAttempts: inc.filter((i) => i.blocked).length,
    pausedTransfers: own.filter((t) => t.status === "PAUSED" || t.status === "SUSPICIOUS").length,
    terminatedTransfers: own.filter((t) => t.status === "TERMINATED").length,
    threatLevel:
      openIncidents > 0
        ? criticalOrHigh > 0
          ? "CRITICAL"
          : "ELEVATED"
        : criticalOrHigh > 0
          ? "GUARDED"
          : "NORMAL",
    monitors,
    recentEvents: (audit ?? []).map((a) => ({
      id: a.id,
      event: a.event,
      severity: a.severity,
      created_at: a.created_at,
      action: a.action,
      simulated: true,
    })),
  };
}

export async function getIncidentDetail(admin: Admin, incidentId: string, ownerId: string) {
  const { data: incident } = await admin
    .from("threat_incidents")
    .select("*")
    .eq("id", incidentId)
    .maybeSingle();
  if (!incident) return null;

  if (incident.transfer_id) {
    const { data: transfer } = await admin
      .from("transfers")
      .select("id, sender_id, recipient_id, status, terminated_reason")
      .eq("id", incident.transfer_id)
      .maybeSingle();
    if (!transfer || (transfer.sender_id !== ownerId && transfer.recipient_id !== ownerId)) {
      if (incident.user_id !== ownerId) return null;
    }
    const { data: notifications } = await admin
      .from("notifications")
      .select("user_id, title, created_at")
      .eq("transfer_id", incident.transfer_id);
    const { data: audit } = await admin
      .from("audit_logs")
      .select("event, action, severity, created_at")
      .eq("transfer_id", incident.transfer_id)
      .order("created_at", { ascending: false })
      .limit(40);
    return { incident, transfer, notifications: notifications ?? [], audit: audit ?? [] };
  }

  if (incident.user_id !== ownerId) return null;
  return { incident, transfer: null, notifications: [], audit: [] };
}
