import { describe, expect, it } from "vitest";

import {
  BLOCKED_EXTENSIONS,
  MAX_FILE_BYTES,
  THREAT_RULES,
  TRUST_START,
  applyTrustDelta,
  clampTrust,
  getTrustStatus,
  isTransferEligible,
  riskBand,
  safeStorageName,
  trustFromEvents,
  validateCoordinates,
  validateFile,
} from "./security-rules";

describe("trust scoring & bands", () => {
  it("clamps to the 0-100 range", () => {
    expect(clampTrust(-40)).toBe(0);
    expect(clampTrust(180)).toBe(100);
    expect(clampTrust(63)).toBe(63);
    expect(clampTrust(0)).toBe(0);
    expect(clampTrust(100)).toBe(100);
  });

  it("applies a negative delta without dropping below zero", () => {
    expect(applyTrustDelta(100, -50)).toBe(50);
    expect(applyTrustDelta(20, -50)).toBe(0);
    expect(applyTrustDelta(10, -15)).toBe(0);
    expect(applyTrustDelta(90, -25)).toBe(65);
  });

  it("recomputes a score from an event history", () => {
    expect(trustFromEvents([])).toBe(TRUST_START);
    expect(trustFromEvents([-15, -20])).toBe(65);
    expect(trustFromEvents([-50, -50, -50])).toBe(0);
  });

  it("maps scores onto standardized trust status bands", () => {
    expect(getTrustStatus(100)).toBe("TRUSTED");
    expect(getTrustStatus(90)).toBe("TRUSTED");
    expect(getTrustStatus(89)).toBe("NORMAL");
    expect(getTrustStatus(75)).toBe("NORMAL");
    expect(getTrustStatus(74)).toBe("CAUTION");
    expect(getTrustStatus(60)).toBe("CAUTION");
    expect(getTrustStatus(59)).toBe("HIGH RISK");
    expect(getTrustStatus(0)).toBe("HIGH RISK");
  });

  it("enforces transfer eligibility threshold (score >= 60)", () => {
    expect(isTransferEligible(100)).toBe(true);
    expect(isTransferEligible(90)).toBe(true);
    expect(isTransferEligible(75)).toBe(true);
    expect(isTransferEligible(60)).toBe(true);
    expect(isTransferEligible(59)).toBe(false);
    expect(isTransferEligible(30)).toBe(false);
    expect(isTransferEligible(0)).toBe(false);
  });

  it("maps scores onto legacy risk bands", () => {
    expect(riskBand(100)).toBe("TRUSTED");
    expect(riskBand(80)).toBe("NORMAL");
    expect(riskBand(65)).toBe("CAUTION");
    expect(riskBand(10)).toBe("HIGH RISK");
  });
});

describe("threat rules specification", () => {
  it("treats integrity failure as critical with -25 trust delta and terminating action", () => {
    const rule = THREAT_RULES.INTEGRITY_FAILURE;
    expect(rule.severity).toBe("critical");
    expect(rule.trustDelta).toBe(-25);
    expect(rule.action).toBe("TERMINATE_TRANSFER");
    expect(rule.blocksTransfer).toBe(true);
  });

  it("penalises token replay with -15 delta and blocks the transfer", () => {
    expect(THREAT_RULES.TOKEN_REPLAY.trustDelta).toBe(-15);
    expect(THREAT_RULES.TOKEN_REPLAY.blocksTransfer).toBe(true);
  });

  it("penalises unauthorized receiver with -20 delta", () => {
    expect(THREAT_RULES.UNAUTHORIZED_RECEIVER.trustDelta).toBe(-20);
    expect(THREAT_RULES.UNAUTHORIZED_RECEIVER.blocksTransfer).toBe(true);
  });

  it("penalises invalid token with -20 delta", () => {
    expect(THREAT_RULES.INVALID_TOKEN.trustDelta).toBe(-20);
    expect(THREAT_RULES.INVALID_TOKEN.blocksTransfer).toBe(true);
  });

  it("never awards positive trust for a threat rule", () => {
    for (const rule of Object.values(THREAT_RULES)) {
      expect(rule.trustDelta).toBeLessThanOrEqual(0);
    }
  });
});

describe("coordinate validation", () => {
  it("validates valid latitude and longitude pairs", () => {
    expect(validateCoordinates(37.7749, -122.4194)).toBe(true);
    expect(validateCoordinates(0, 0)).toBe(true);
    expect(validateCoordinates(-90, 180)).toBe(true);
    expect(validateCoordinates(90, -180)).toBe(true);
  });

  it("rejects invalid latitude or longitude", () => {
    expect(validateCoordinates(91, 0)).toBe(false);
    expect(validateCoordinates(-91, 0)).toBe(false);
    expect(validateCoordinates(0, 181)).toBe(false);
    expect(validateCoordinates(0, -181)).toBe(false);
    expect(validateCoordinates(NaN, 0)).toBe(false);
    expect(validateCoordinates(0, Infinity)).toBe(false);
  });
});

describe("file validation", () => {
  it("accepts an ordinary document", () => {
    expect(validateFile({ name: "thesis.pdf", size: 1024, type: "application/pdf" })).toBeNull();
  });

  it("rejects empty files and oversized files", () => {
    expect(validateFile({ name: "a.pdf", size: 0, type: "application/pdf" })).toBeTruthy();
    expect(
      validateFile({ name: "a.pdf", size: MAX_FILE_BYTES + 1, type: "application/pdf" }),
    ).toBeTruthy();
  });

  it("rejects executable extensions", () => {
    for (const ext of BLOCKED_EXTENSIONS) {
      expect(validateFile({ name: `payload.${ext}`, size: 10, type: "" })).toBeTruthy();
    }
  });
});

describe("storage naming", () => {
  it("scopes the object path to the owner and strips unsafe characters", () => {
    const path = safeStorageName("2f1c9b0e", "my report (final).pdf");
    expect(path.startsWith("2f1c9b0e/")).toBe(true);
    expect(path).not.toMatch(/[()\s]/);
  });
});
