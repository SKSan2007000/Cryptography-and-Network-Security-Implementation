import { describe, expect, it } from "vitest";
import {
  getTrustStatus,
  isTransferEligible,
  clampTrust,
  applyTrustDelta,
  validateCoordinates,
  THREAT_RULES,
} from "./security-rules";

describe("Trust Engine Core & Thresholds", () => {
  describe("Trust Status Classification", () => {
    it("classifies scores 90-100 as TRUSTED", () => {
      expect(getTrustStatus(100)).toBe("TRUSTED");
      expect(getTrustStatus(95)).toBe("TRUSTED");
      expect(getTrustStatus(90)).toBe("TRUSTED");
    });

    it("classifies scores 75-89 as NORMAL", () => {
      expect(getTrustStatus(89)).toBe("NORMAL");
      expect(getTrustStatus(80)).toBe("NORMAL");
      expect(getTrustStatus(75)).toBe("NORMAL");
    });

    it("classifies scores 60-74 as CAUTION", () => {
      expect(getTrustStatus(74)).toBe("CAUTION");
      expect(getTrustStatus(68)).toBe("CAUTION");
      expect(getTrustStatus(60)).toBe("CAUTION");
    });

    it("classifies scores 0-59 as HIGH RISK", () => {
      expect(getTrustStatus(59)).toBe("HIGH RISK");
      expect(getTrustStatus(40)).toBe("HIGH RISK");
      expect(getTrustStatus(10)).toBe("HIGH RISK");
      expect(getTrustStatus(0)).toBe("HIGH RISK");
    });
  });

  describe("Transfer-Level Trust Gate Enforcement", () => {
    it("allows transfers for TRUSTED, NORMAL, and CAUTION users (score >= 60)", () => {
      expect(isTransferEligible(100)).toBe(true);
      expect(isTransferEligible(85)).toBe(true);
      expect(isTransferEligible(60)).toBe(true);
    });

    it("strictly blocks transfers when receiver trust score is < 60", () => {
      expect(isTransferEligible(59)).toBe(false);
      expect(isTransferEligible(50)).toBe(false);
      expect(isTransferEligible(20)).toBe(false);
      expect(isTransferEligible(0)).toBe(false);
    });
  });

  describe("Dynamic Threat Deductions", () => {
    it("correctly penalizes multiple progressive security violations", () => {
      let score = 100;

      // 1. Suspicious IP / Expired session (-10)
      score = applyTrustDelta(score, THREAT_RULES.SUSPICIOUS_IP_CHANGE.trustDelta);
      expect(score).toBe(90);
      expect(getTrustStatus(score)).toBe("TRUSTED");
      expect(isTransferEligible(score)).toBe(true);

      // 2. Token replay (-15)
      score = applyTrustDelta(score, THREAT_RULES.TOKEN_REPLAY.trustDelta);
      expect(score).toBe(75);
      expect(getTrustStatus(score)).toBe("NORMAL");
      expect(isTransferEligible(score)).toBe(true);

      // 3. Unauthorized receiver attempt (-20)
      score = applyTrustDelta(score, THREAT_RULES.UNAUTHORIZED_RECEIVER.trustDelta);
      expect(score).toBe(55);
      expect(getTrustStatus(score)).toBe("HIGH RISK");
      expect(isTransferEligible(score)).toBe(false); // NOW BLOCKED!

      // 4. Integrity failure (-25)
      score = applyTrustDelta(score, THREAT_RULES.INTEGRITY_FAILURE.trustDelta);
      expect(score).toBe(30);
      expect(getTrustStatus(score)).toBe("HIGH RISK");
      expect(isTransferEligible(score)).toBe(false);
    });

    it("handles applying trust deltas with clamping boundaries", () => {
      expect(applyTrustDelta(100, -25)).toBe(75);
      expect(applyTrustDelta(50, -60)).toBe(0);
      expect(applyTrustDelta(90, 20)).toBe(100);
      expect(clampTrust(-10)).toBe(0);
      expect(clampTrust(150)).toBe(100);
    });
  });

  describe("Location Geolocation Coordinates Verification", () => {
    it("validates realistic global GPS coordinates", () => {
      expect(validateCoordinates(40.7128, -74.006)).toBe(true); // New York
      expect(validateCoordinates(51.5074, -0.1278)).toBe(true); // London
      expect(validateCoordinates(35.6762, 139.6503)).toBe(true); // Tokyo
      expect(validateCoordinates(13.0827, 80.2707)).toBe(true); // Chennai
    });

    it("rejects out-of-range coordinates", () => {
      expect(validateCoordinates(95.0, 10.0)).toBe(false);
      expect(validateCoordinates(-92.0, 10.0)).toBe(false);
      expect(validateCoordinates(10.0, 190.0)).toBe(false);
      expect(validateCoordinates(10.0, -185.0)).toBe(false);
    });
  });
});
