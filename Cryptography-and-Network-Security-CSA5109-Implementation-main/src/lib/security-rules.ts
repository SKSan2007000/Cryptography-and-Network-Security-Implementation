/**
 * SentinelCrypt trust & threat rules.
 *
 * These are APPLICATION-DEFINED rules, documented and auditable. The trust score
 * is not an industry-standard metric — it is a transparent heuristic used by this
 * platform to summarise detected session/token/integrity anomalies.
 */

export type ThreatType =
  | "EXPIRED_SESSION"
  | "INVALID_TOKEN"
  | "TOKEN_REPLAY"
  | "EXCESSIVE_FAILED_DOWNLOADS"
  | "CONCURRENT_SESSIONS"
  | "SUSPICIOUS_IP_CHANGE"
  | "DEVICE_CHANGE"
  | "INTEGRITY_FAILURE"
  | "UNAUTHORIZED_RECEIVER"
  | "TRANSFER_EXPIRED"
  | "DOWNLOAD_LIMIT_EXCEEDED"
  | "ABNORMAL_REQUEST_RATE";

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type ResponseAction =
  "LOG_ONLY" | "PAUSE_TRANSFER" | "TERMINATE_TRANSFER" | "REVOKE_SESSION";

export type ThreatRule = {
  type: ThreatType;
  label: string;
  description: string;
  severity: Severity;
  trustDelta: number;
  action: ResponseAction;
  blocksTransfer: boolean;
  notifySender: boolean;
  notifyReceiver: boolean;
};

export const THREAT_RULES: Record<ThreatType, ThreatRule> = {
  INTEGRITY_FAILURE: {
    type: "INTEGRITY_FAILURE",
    label: "Integrity verification failure",
    description: "SHA-256 fingerprint of the decrypted file did not match the sender's record.",
    severity: "critical",
    trustDelta: -25,
    action: "TERMINATE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: true,
  },
  INVALID_TOKEN: {
    type: "INVALID_TOKEN",
    label: "Invalid transfer token",
    description: "A download was attempted with a token that does not match the stored hash.",
    severity: "high",
    trustDelta: -20,
    action: "TERMINATE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: false,
  },
  TOKEN_REPLAY: {
    type: "TOKEN_REPLAY",
    label: "Token replay detected",
    description: "A single-use transfer token was presented again after being consumed.",
    severity: "high",
    trustDelta: -15,
    action: "TERMINATE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: true,
  },
  UNAUTHORIZED_RECEIVER: {
    type: "UNAUTHORIZED_RECEIVER",
    label: "Unauthorized receiver",
    description: "An account that is not the designated recipient attempted to access the payload.",
    severity: "high",
    trustDelta: -20,
    action: "PAUSE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: false,
  },
  EXPIRED_SESSION: {
    type: "EXPIRED_SESSION",
    label: "Expired session",
    description: "The application session used for this request had passed its expiry time.",
    severity: "medium",
    trustDelta: -10,
    action: "REVOKE_SESSION",
    blocksTransfer: true,
    notifySender: false,
    notifyReceiver: true,
  },
  SUSPICIOUS_IP_CHANGE: {
    type: "SUSPICIOUS_IP_CHANGE",
    label: "Suspicious IP change",
    description: "The client IP changed during an active transfer session.",
    severity: "medium",
    trustDelta: -10,
    action: "PAUSE_TRANSFER",
    blocksTransfer: false,
    notifySender: true,
    notifyReceiver: true,
  },
  DEVICE_CHANGE: {
    type: "DEVICE_CHANGE",
    label: "New device / session anomaly",
    description: "The request came from a device fingerprint not previously seen for this account.",
    severity: "medium",
    trustDelta: -10,
    action: "LOG_ONLY",
    blocksTransfer: false,
    notifySender: false,
    notifyReceiver: true,
  },
  CONCURRENT_SESSIONS: {
    type: "CONCURRENT_SESSIONS",
    label: "Multiple concurrent sessions",
    description: "Several active sessions were observed for the same account at the same time.",
    severity: "medium",
    trustDelta: -10,
    action: "LOG_ONLY",
    blocksTransfer: false,
    notifySender: false,
    notifyReceiver: true,
  },
  EXCESSIVE_FAILED_DOWNLOADS: {
    type: "EXCESSIVE_FAILED_DOWNLOADS",
    label: "Excessive failed download attempts",
    description: "Repeated failed download attempts were recorded for this transfer.",
    severity: "medium",
    trustDelta: -15,
    action: "PAUSE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: true,
  },
  DOWNLOAD_LIMIT_EXCEEDED: {
    type: "DOWNLOAD_LIMIT_EXCEEDED",
    label: "Download limit exceeded",
    description: "The configured maximum download count for this transfer was reached.",
    severity: "low",
    trustDelta: -15,
    action: "TERMINATE_TRANSFER",
    blocksTransfer: true,
    notifySender: true,
    notifyReceiver: false,
  },
  TRANSFER_EXPIRED: {
    type: "TRANSFER_EXPIRED",
    label: "Expired transfer",
    description: "The transfer was accessed after its expiry timestamp.",
    severity: "low",
    trustDelta: 0,
    action: "TERMINATE_TRANSFER",
    blocksTransfer: true,
    notifySender: false,
    notifyReceiver: false,
  },
  ABNORMAL_REQUEST_RATE: {
    type: "ABNORMAL_REQUEST_RATE",
    label: "Abnormal repeated requests",
    description: "An unusually high request rate was observed against this transfer.",
    severity: "medium",
    trustDelta: -15,
    action: "PAUSE_TRANSFER",
    blocksTransfer: false,
    notifySender: true,
    notifyReceiver: false,
  },
};

export const TRUST_START = 100;
export const TRUST_MINIMUM_REQUIRED = 60;

export function clampTrust(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}

export function applyTrustDelta(current: number, delta: number): number {
  return clampTrust(current + delta);
}

export function trustFromEvents(deltas: number[], start = TRUST_START): number {
  return clampTrust(deltas.reduce((acc, d) => acc + d, start));
}

export type TrustStatus = "TRUSTED" | "NORMAL" | "CAUTION" | "HIGH RISK";

export function getTrustStatus(score: number): TrustStatus {
  if (score >= 90) return "TRUSTED";
  if (score >= 75) return "NORMAL";
  if (score >= 60) return "CAUTION";
  return "HIGH RISK";
}

export type RiskBand = TrustStatus;

export function riskBand(score: number): RiskBand {
  return getTrustStatus(score);
}

export function isTransferEligible(score: number): boolean {
  return score >= TRUST_MINIMUM_REQUIRED;
}

export function validateCoordinates(lat?: number | null, lng?: number | null): boolean {
  if (lat === null || lat === undefined || lng === null || lng === undefined) return false;
  if (typeof lat !== "number" || typeof lng !== "number") return false;
  if (Number.isNaN(lat) || Number.isNaN(lng)) return false;
  return lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180;
}

export const TRANSFER_STATES = [
  "CREATED",
  "ENCRYPTING",
  "ENCRYPTED",
  "TRANSFERRING",
  "VERIFYING",
  "COMPLETED",
  "PAUSED",
  "SUSPICIOUS",
  "TERMINATED",
  "EXPIRED",
  "FAILED",
] as const;

export type TransferState = (typeof TRANSFER_STATES)[number];

export const MAX_FILE_BYTES = 25 * 1024 * 1024; // documented capstone limit: 25 MB

export const BLOCKED_EXTENSIONS = ["exe", "bat", "cmd", "com", "scr", "msi", "dll", "js", "vbs"];

export function safeStorageName(userId: string, originalName: string): string {
  const ext = originalName.includes(".")
    ? originalName
        .split(".")
        .pop()!
        .replace(/[^a-zA-Z0-9]/g, "")
        .slice(0, 10)
    : "bin";
  const rand = globalThis.crypto.randomUUID();
  return `${userId}/${rand}.${ext || "bin"}.enc`;
}

export function validateFile(file: { name: string; size: number; type: string }): string | null {
  if (file.size === 0) return "The selected file is empty.";
  if (file.size > MAX_FILE_BYTES)
    return `File exceeds the ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB limit for this platform.`;
  if (/[\\/]|\.\./.test(file.name)) return "File name contains illegal path characters.";
  const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
  if (BLOCKED_EXTENSIONS.includes(ext)) return `Files of type .${ext} are not accepted.`;
  return null;
}
