/**
 * SentinelCrypt transfer state machine (shared by client and server).
 *
 * Successful path:   CREATED -> ENCRYPTING -> ENCRYPTED -> TRANSFERRING -> VERIFYING -> COMPLETED
 * Integrity failure: TRANSFERRING -> VERIFYING -> SUSPICIOUS -> TERMINATED
 * Expiry:            TRANSFERRING -> EXPIRED
 *
 * Terminal states can never be resurrected into COMPLETED.
 */
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

/** States from which a receiver may legitimately start a verified download. */
export const DOWNLOADABLE_STATES: readonly TransferState[] = [
  "ENCRYPTED",
  "TRANSFERRING",
  "VERIFYING",
];

export const TERMINAL_STATES: readonly TransferState[] = [
  "COMPLETED",
  "TERMINATED",
  "EXPIRED",
  "FAILED",
];

export function isDownloadable(status: string): boolean {
  return (DOWNLOADABLE_STATES as readonly string[]).includes(status);
}

export function isTerminal(status: string): boolean {
  return (TERMINAL_STATES as readonly string[]).includes(status);
}

/** Human-readable reason a download cannot proceed, or null when it can. */
export function downloadBlockReason(status: string): string | null {
  if (isDownloadable(status)) return null;
  switch (status) {
    case "COMPLETED":
      return "This transfer has already been downloaded and verified.";
    case "TERMINATED":
      return "This transfer was terminated by the threat engine.";
    case "EXPIRED":
      return "This transfer has expired.";
    case "SUSPICIOUS":
      return "This transfer is flagged as suspicious and is under review.";
    case "PAUSED":
      return "This transfer is paused pending security review.";
    case "FAILED":
      return "This transfer failed and cannot be downloaded.";
    default:
      return `Transfer is ${status.toLowerCase()}`;
  }
}
