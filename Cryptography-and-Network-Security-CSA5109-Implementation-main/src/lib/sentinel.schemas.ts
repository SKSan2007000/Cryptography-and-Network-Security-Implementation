import { z } from "zod";

import { MAX_FILE_BYTES } from "./security-rules";

export const sessionSchema = z.object({
  deviceFingerprint: z.string().min(3).max(120),
});

export const logEventSchema = z.object({
  event: z.string().min(2).max(64),
  transferId: z.string().uuid().nullish(),
  severity: z.enum(["info", "low", "medium", "high", "critical"]).default("info"),
  action: z.string().max(64).nullish(),
  metadata: z.record(z.unknown()).optional(),
});

export const createTransferSchema = z.object({
  recipientId: z.string().uuid(),
  fileName: z
    .string()
    .min(1)
    .max(255)
    .refine((v) => !/[\\/]|\.\./.test(v), "Illegal file name"),
  mimeType: z.string().min(1).max(180),
  sizeBytes: z.number().int().positive().max(MAX_FILE_BYTES),
  storagePath: z.string().min(3).max(300),
  iv: z.string().min(8).max(64),
  originalSha256: z.string().length(64),
  ciphertextSha256: z.string().length(64),
  wrappedKey: z.string().min(64),
  token: z.string().length(64),
  senderTokenWrapped: z.string().min(64).max(2048).optional(),
  expiresInHours: z.number().int().min(1).max(720),
  maxDownloads: z.number().int().min(1).max(20),
  securityLevel: z.enum(["standard", "high", "maximum"]),
  metrics: z.record(z.number()).default({}),
  senderLatitude: z.number().min(-90).max(90).nullish(),
  senderLongitude: z.number().min(-180).max(180).nullish(),
  senderLocationTimestamp: z.string().nullish(),
});

export const downloadSchema = z.object({
  transferId: z.string().uuid(),
  token: z.string().min(8).max(128),
  deviceFingerprint: z.string().min(3).max(120),
  receiverLatitude: z.number().min(-90).max(90).nullish(),
  receiverLongitude: z.number().min(-180).max(180).nullish(),
  receiverLocationTimestamp: z.string().nullish(),
});

export const integritySchema = z.object({
  transferId: z.string().uuid(),
  computedSha256: z.string().length(64),
  metrics: z.record(z.number()).default({}),
});

export const simulateSchema = z.object({
  type: z.enum([
    "EXPIRED_SESSION",
    "INVALID_TOKEN",
    "TOKEN_REPLAY",
    "EXCESSIVE_FAILED_DOWNLOADS",
    "CONCURRENT_SESSIONS",
    "SUSPICIOUS_IP_CHANGE",
    "DEVICE_CHANGE",
    "INTEGRITY_FAILURE",
    "UNAUTHORIZED_RECEIVER",
    "TRANSFER_EXPIRED",
    "DOWNLOAD_LIMIT_EXCEEDED",
    "ABNORMAL_REQUEST_RATE",
  ]),
  transferId: z.string().uuid().nullish(),
});

export const loginAttemptSchema = z.object({
  email: z.string().email().max(200),
  success: z.boolean(),
});

export const adminActionSchema = z.object({
  action: z.enum([
    "REVOKE_SESSIONS",
    "SUSPEND_USER",
    "REINSTATE_USER",
    "RESET_TRUST",
    "TERMINATE_TRANSFER",
  ]),
  targetUserId: z.string().uuid(),
  transferId: z.string().uuid().nullish(),
});
