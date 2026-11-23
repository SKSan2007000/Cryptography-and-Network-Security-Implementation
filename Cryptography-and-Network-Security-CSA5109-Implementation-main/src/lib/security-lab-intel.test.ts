import { describe, expect, it } from "vitest";

import {
  buildIncidentTimeline,
  labIntel,
  riskScoreFrom,
  securityPosture,
  sessionRef,
  transferRef,
} from "./security-lab-intel";

describe("security lab intelligence helpers", () => {
  it("scores critical threats higher than low ones", () => {
    expect(riskScoreFrom("critical", -50)).toBeGreaterThan(riskScoreFrom("low", -10));
    expect(riskScoreFrom("critical", -50)).toBeLessThanOrEqual(100);
    expect(riskScoreFrom(null, 0)).toBeGreaterThanOrEqual(0);
  });

  it("formats stable transfer and session references", () => {
    expect(transferRef("4f2a91c8-1111-2222-3333-444455556666")).toBe("TR-4F2A91C8");
    expect(sessionRef(null)).toBe("LAB-SESSION-NONE");
    expect(sessionRef("abcde123-0000-0000-0000-000000000000")).toBe("LAB-SESSION-ABCDE");
  });

  it("labels simulated geolocation and never claims real identity", () => {
    const intel = labIntel({
      scenario: "TOKEN_REPLAY",
      actorLabel: "Unauthorized Test User",
      observedIp: "203.0.113.77",
      sessionId: "abcde123-0000-0000-0000-000000000000",
      deviceFingerprint: "lab-known-device",
      threatType: "TOKEN_REPLAY",
      severity: "high",
      trustDelta: -30,
    });
    expect(intel.regionSimulated).toBe(true);
    expect(intel.sourceIpSimulated).toBe(true);
    expect(intel.severity).toBe("HIGH");
    expect(intel.riskScore).toBeGreaterThan(70);
  });

  it("orders the incident timeline chronologically", () => {
    const timeline = buildIncidentTimeline([
      { created_at: "2026-01-01T08:31:00Z", event: "TRANSFER_PAUSED", action: "PAUSE_TRANSFER" },
      { created_at: "2026-01-01T08:30:00Z", event: "TRANSFER_CREATED" },
    ]);
    expect(timeline.map((t) => t.label)).toEqual(["TRANSFER CREATED", "TRANSFER PAUSED"]);
    expect(timeline[1]?.detail).toBe("pause transfer");
  });

  it("derives posture from stored state", () => {
    expect(securityPosture({ openIncidents: 1, criticalOrHighLast24h: 1, trustScore: 40 })).toBe(
      "ACTIVE INCIDENT",
    );
    expect(securityPosture({ openIncidents: 0, criticalOrHighLast24h: 1, trustScore: 100 })).toBe(
      "ELEVATED RISK",
    );
    expect(securityPosture({ openIncidents: 0, criticalOrHighLast24h: 0, trustScore: 100 })).toBe(
      "SECURE",
    );
  });
});
