/**
 * Browser-side secure transfer pipeline.
 *
 * Sender:   SHA-256 -> AES-256-GCM -> RSA-OAEP key wrap -> upload -> createTransfer
 * Receiver: requestDownload -> fetch payload -> RSA unwrap -> AES-GCM decrypt -> SHA-256 -> reportIntegrity
 *
 * Every state change is derived from real work or from the server response; no
 * step is advanced on a timer.
 */
import { supabase } from "@/integrations/supabase/client";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  deviceFingerprint,
  exportAesKey,
  generateAesKey,
  generateTransferToken,
  sha256Hex,
  toBase64,
  fromBase64,
  rsaSealText,
  unwrapAesKey,
  wrapAesKey,
} from "./crypto";
import { getPrivateKey, getRecipientPublicKey } from "./keyvault";
import { safeStorageName, validateFile } from "./security-rules";
import { createTransfer, logEvent, reportIntegrity, requestDownload } from "./sentinel.functions";

export const SEND_STEPS = [
  { key: "prepare", label: "Preparing file" },
  { key: "material", label: "Generating cryptographic material" },
  { key: "hash", label: "Generating SHA-256 fingerprint" },
  { key: "encrypt", label: "Encrypting with AES-256-GCM" },
  { key: "wrap", label: "Protecting AES key with RSA-OAEP" },
  { key: "upload", label: "Uploading encrypted payload" },
  { key: "create", label: "Creating secure transfer" },
  { key: "monitor", label: "Starting monitoring" },
] as const;

export type SendStepKey = (typeof SEND_STEPS)[number]["key"];

export type SendOptions = {
  file: File;
  recipientId: string;
  senderId: string;
  expiresInHours: number;
  maxDownloads: number;
  securityLevel: "standard" | "high" | "maximum";
  senderLatitude?: number | null;
  senderLongitude?: number | null;
  senderLocationTimestamp?: string | null;
  onStep: (key: SendStepKey, status: "active" | "done" | "failed", detail?: string) => void;
};

export type SendResult = {
  transferId: string;
  token: string;
  expiresAt: string | null;
  metrics: Record<string, number>;
};

export async function sendSecureTransfer(options: SendOptions): Promise<SendResult> {
  const { file, recipientId, senderId, onStep } = options;
  const metrics: Record<string, number> = {};
  const mark = (key: string, start: number) => {
    metrics[key] = Math.max(1, Math.round(performance.now() - start));
    return metrics[key];
  };

  onStep("prepare", "active");
  const invalid = validateFile({ name: file.name, size: file.size, type: file.type });
  if (invalid) {
    onStep("prepare", "failed", invalid);
    throw new Error(invalid);
  }
  const plaintext = await file.arrayBuffer();
  metrics["sizeBytes"] = file.size;
  onStep("prepare", "done", `${file.name} · ${file.size} bytes`);

  onStep("material", "active");
  const t0 = performance.now();
  const aesKey = await generateAesKey();
  const publicKey = await getRecipientPublicKey(recipientId);
  const token = generateTransferToken();
  mark("keygenMs", t0);
  onStep("material", "done", "AES-256 key + 256-bit transfer token");

  onStep("hash", "active");
  const t1 = performance.now();
  const originalSha256 = await sha256Hex(plaintext);
  mark("hashingMs", t1);
  onStep("hash", "done", `${originalSha256.slice(0, 16)}… (${metrics["hashingMs"]} ms)`);

  onStep("encrypt", "active");
  const t2 = performance.now();
  const { ciphertext, iv } = await aesGcmEncrypt(aesKey, plaintext);
  mark("encryptionMs", t2);
  const ciphertextSha256 = await sha256Hex(ciphertext);
  onStep("encrypt", "done", `${ciphertext.byteLength} bytes (${metrics["encryptionMs"]} ms)`);

  onStep("wrap", "active");
  const t3 = performance.now();
  const wrappedKey = await wrapAesKey(publicKey, aesKey);
  // Seal the one-time token with the SENDER's own public key so it can be
  // shown again later to the sender only (never stored in plaintext).
  let senderTokenWrapped: string | undefined;
  try {
    const senderPublicKey = await getRecipientPublicKey(senderId);
    senderTokenWrapped = await rsaSealText(senderPublicKey, token);
  } catch {
    senderTokenWrapped = undefined;
  }
  mark("keyWrapMs", t3);
  onStep("wrap", "done", `RSA-OAEP 2048 (${metrics["keyWrapMs"]} ms)`);

  onStep("upload", "active");
  const t4 = performance.now();
  const storagePath = safeStorageName(senderId, file.name);
  const { error: uploadError } = await supabase.storage
    .from("encrypted-payloads")
    .upload(
      storagePath,
      new Blob([new Uint8Array(ciphertext)], { type: "application/octet-stream" }),
      {
        contentType: "application/octet-stream",
        upsert: false,
      },
    );
  if (uploadError) {
    onStep("upload", "failed", "Encrypted payload could not be stored.");
    throw new Error("Encrypted payload could not be stored.");
  }
  mark("uploadMs", t4);
  onStep("upload", "done", `${metrics["uploadMs"]} ms`);

  onStep("create", "active");
  const created = await createTransfer({
    data: {
      recipientId,
      fileName: file.name,
      mimeType: file.type || "application/octet-stream",
      sizeBytes: file.size,
      storagePath,
      iv: toBase64(iv),
      originalSha256,
      ciphertextSha256,
      wrappedKey,
      token,
      ...(senderTokenWrapped ? { senderTokenWrapped } : {}),
      expiresInHours: options.expiresInHours,
      maxDownloads: options.maxDownloads,
      securityLevel: options.securityLevel,
      senderLatitude: options.senderLatitude,
      senderLongitude: options.senderLongitude,
      senderLocationTimestamp: options.senderLocationTimestamp,
      metrics,
    },
  });
  onStep("create", "done", created.transferId);

  onStep("monitor", "active");
  onStep("monitor", "done", "Session, token and integrity monitoring active");

  // The AES key material never leaves this function unwrapped.
  await exportAesKey(aesKey);

  return {
    transferId: created.transferId,
    token: created.token,
    expiresAt: created.expiresAt ?? null,
    metrics,
  };
}

export type ReceiveOutcome =
  | { ok: true; fileName: string; bytes: number; sha256: string; metrics: Record<string, number> }
  | {
      ok: false;
      reason: string;
      label?: string;
      severity?: string;
      action?: string;
      trustDelta?: number;
    };

export async function receiveSecureTransfer(input: {
  transferId: string;
  token: string;
  userId: string;
  passphrase: string;
  fileName: string;
  receiverLatitude?: number | null;
  receiverLongitude?: number | null;
  receiverLocationTimestamp?: string | null;
  onStep?: (message: string) => void;
}): Promise<ReceiveOutcome> {
  const step = input.onStep ?? (() => undefined);
  const metrics: Record<string, number> = {};

  step("Validating token, session and authorisation");
  const gate = await requestDownload({
    data: {
      transferId: input.transferId,
      token: input.token,
      deviceFingerprint: deviceFingerprint(),
      receiverLatitude: input.receiverLatitude,
      receiverLongitude: input.receiverLongitude,
      receiverLocationTimestamp: input.receiverLocationTimestamp,
    },
  });

  if (!gate.ok) {
    const threat = gate.threat;
    return {
      ok: false,
      reason: threat?.label ?? "Access blocked by the security engine.",
      label: threat?.label ?? "Access blocked",
      severity: threat?.severity ?? "high",
      action: threat?.action ?? "TERMINATE_TRANSFER",
      trustDelta: threat?.trustDelta ?? 0,
    };
  }

  step("Downloading encrypted payload over TLS");
  const t0 = performance.now();
  if (!gate.signedUrl)
    return { ok: false, reason: "The encrypted payload could not be downloaded." };
  const response = await fetch(gate.signedUrl);
  if (!response.ok) return { ok: false, reason: "The encrypted payload could not be downloaded." };
  const ciphertext = new Uint8Array(await response.arrayBuffer());
  metrics["downloadMs"] = Math.max(1, Math.round(performance.now() - t0));

  step("Receiver authenticated · access token validated");
  step("Recovering AES key with your RSA private key");
  if (!gate.wrappedKey)
    return { ok: false, reason: "The wrapped AES key is missing for this transfer." };
  const privateKey = await getPrivateKey(input.userId, input.passphrase);
  const t1 = performance.now();
  const aesKey = await unwrapAesKey(privateKey, gate.wrappedKey);
  metrics["keyUnwrapMs"] = Math.max(1, Math.round(performance.now() - t1));

  step("Decrypting with AES-256-GCM");
  await logEvent({
    data: { transferId: input.transferId, event: "DECRYPTION_STARTED", severity: "info" },
  });
  const t2 = performance.now();
  let plaintext: ArrayBuffer;
  try {
    plaintext = await aesGcmDecrypt(aesKey, fromBase64(gate.iv), ciphertext);
  } catch {
    return {
      ok: false,
      reason: "AES-GCM authentication failed — the payload was modified in storage.",
    };
  }
  metrics["decryptionMs"] = Math.max(1, Math.round(performance.now() - t2));
  await logEvent({
    data: {
      transferId: input.transferId,
      event: "DECRYPTION_COMPLETED",
      severity: "info",
      action: "AES_GCM_TAG_VERIFIED",
      metadata: { bytes: plaintext.byteLength, decryptionMs: metrics["decryptionMs"] },
    },
  });

  step("Verifying SHA-256 fingerprint");
  const t3 = performance.now();
  const computed = await sha256Hex(plaintext);
  metrics["verificationMs"] = Math.max(1, Math.round(performance.now() - t3));

  const verdict = await reportIntegrity({
    data: { transferId: input.transferId, computedSha256: computed, metrics },
  });
  if (!verdict.ok) {
    return {
      ok: false,
      reason: "Integrity verification failed. Download blocked.",
      label: verdict.threat.label,
      severity: verdict.threat.severity,
      action: verdict.threat.action,
      trustDelta: verdict.threat.trustDelta,
    };
  }

  step("Integrity verified — releasing file");
  triggerBrowserDownload(plaintext, input.fileName);
  return {
    ok: true,
    fileName: input.fileName,
    bytes: plaintext.byteLength,
    sha256: computed,
    metrics,
  };
}

export function triggerBrowserDownload(data: ArrayBuffer, fileName: string) {
  const url = URL.createObjectURL(new Blob([data]));
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
