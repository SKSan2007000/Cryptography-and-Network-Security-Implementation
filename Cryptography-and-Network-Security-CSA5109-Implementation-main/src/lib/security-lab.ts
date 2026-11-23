/**
 * Controlled Security Testing Lab — shared (client-safe) scenario catalogue.
 *
 * Every scenario below drives the real application code path (the shared
 * download gate, the real threat engine, the real integrity comparison) against
 * dedicated LAB TEST transfers and LAB TEST accounts. Nothing here attacks any
 * external system, and no production user file is ever modified.
 */

export const LAB_SCENARIOS = [
  "INVALID_TOKEN",
  "TOKEN_REPLAY",
  "UNAUTHORIZED_RECEIVER",
  "EXPIRED_TRANSFER",
  "INTEGRITY_TAMPERING",
  "SUSPICIOUS_SESSION",
  "ABNORMAL_DOWNLOAD",
] as const;

export type LabScenario = (typeof LAB_SCENARIOS)[number];

export type LabScenarioSpec = {
  id: LabScenario;
  title: string;
  summary: string;
  executes: string;
  /** Scenarios that must know the one-time token always provision a fresh test transfer. */
  requiresFreshTransfer: boolean;
};

export const LAB_SCENARIO_SPECS: Record<LabScenario, LabScenarioSpec> = {
  INVALID_TOKEN: {
    id: "INVALID_TOKEN",
    title: "Invalid Transfer Token",
    summary: "The test receiver presents a token that does not match the stored hash.",
    executes: "Real constant-time token-hash comparison in the download gate.",
    requiresFreshTransfer: false,
  },
  TOKEN_REPLAY: {
    id: "TOKEN_REPLAY",
    title: "Token Replay",
    summary: "A one-time token is consumed legitimately, then presented a second time.",
    executes: "Real single-use enforcement (token_used_at) in the download gate.",
    requiresFreshTransfer: true,
  },
  UNAUTHORIZED_RECEIVER: {
    id: "UNAUTHORIZED_RECEIVER",
    title: "Unauthorized Receiver",
    summary: "A test account that is not the recipient attempts to open the payload.",
    executes: "Real server-side recipient authorisation check.",
    requiresFreshTransfer: true,
  },
  EXPIRED_TRANSFER: {
    id: "EXPIRED_TRANSFER",
    title: "Expired Transfer",
    summary: "Access is attempted against a test transfer whose expiry has passed.",
    executes: "Real expiry validation in the download gate.",
    requiresFreshTransfer: true,
  },
  INTEGRITY_TAMPERING: {
    id: "INTEGRITY_TAMPERING",
    title: "Integrity Tampering",
    summary: "The lab's own encrypted test payload is modified in storage and re-verified.",
    executes: "Real AES-256-GCM authentication + SHA-256 comparison.",
    requiresFreshTransfer: true,
  },
  SUSPICIOUS_SESSION: {
    id: "SUSPICIOUS_SESSION",
    title: "Suspicious Session / Network Anomaly",
    summary: "An unrecognised device fingerprint and differing network source are observed.",
    executes: "Real device/session anomaly evaluation and threat rules.",
    requiresFreshTransfer: false,
  },
  ABNORMAL_DOWNLOAD: {
    id: "ABNORMAL_DOWNLOAD",
    title: "Abnormal Download Attempts",
    summary: "Repeated download attempts are made until the configured limit is exceeded.",
    executes: "Real download-count enforcement in the download gate.",
    requiresFreshTransfer: true,
  },
};

export const SOURCE_EVIDENCE_DISCLAIMER =
  "The platform identifies the session, device, account and network evidence observed by the application. This does not independently establish the attacker's real-world identity.";

export type LabEvidence = {
  actorId: string;
  actorLabel: string;
  sessionId: string | null;
  deviceId: string | null;
  deviceFingerprint: string;
  ipAddress: string | null;
  userAgent: string | null;
  transferId: string;
  timestamp: string;
  scenario: LabScenario;
  attemptCount: number;
};

export type LabIntegrityComparison = {
  expectedSha256: string;
  computedSha256: string;
  match: boolean;
  gcmAuthenticated: boolean;
};

export type LabRunResult = {
  scenario: LabScenario;
  title: string;
  blocked: boolean;
  outcome: string;
  stage: string | null;
  threatType: string | null;
  severity: string | null;
  responseAction: string | null;
  trustBefore: number;
  trustAfter: number;
  transferStatusBefore: string;
  transferStatusAfter: string;
  incidentId: string | null;
  auditEvents: string[];
  notifications: { userId: string; role: "sender" | "receiver"; title: string }[];
  evidence: LabEvidence;
  integrity: LabIntegrityComparison | null;
  /** Short display reference, e.g. TR-4F2A91C8. */
  transferRef: string;
  fileName: string;
  /** Explicitly simulated threat-source intelligence for the demonstration. */
  intel: import("./security-lab-intel").LabThreatIntel;
  /** Persisted incident narrative rebuilt from audit rows. */
  timeline: import("./security-lab-intel").LabTimelineEntry[];
  senderNotified: boolean;
  receiverConfirmationRequired: boolean;
  detectionSummary: string;
};

export type LabDashboard = {
  posture: import("./security-lab-intel").SecurityPosture;
  trustScore: number;
  activeTransfers: number;
  openIncidents: number;
  blockedAttempts: number;
  pausedTransfers: number;
  terminatedTransfers: number;
  threatLevel: string;
  monitors: {
    id: string;
    ref: string;
    status: string;
    fileName: string;
    receiverEmail: string;
    downloadCount: number;
    maxDownloads: number;
    expiresAt: string;
    lastEvent: string | null;
    lastEventAt: string | null;
  }[];
  recentEvents: {
    id: string;
    event: string;
    severity: string;
    created_at: string;
    action: string | null;
    simulated: boolean;
  }[];
};

export type ReceiverDecision = "CONFIRMED" | "DENIED";
