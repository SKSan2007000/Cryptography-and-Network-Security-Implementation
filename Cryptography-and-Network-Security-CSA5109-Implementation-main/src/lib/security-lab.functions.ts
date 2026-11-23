import { createServerFn } from "@tanstack/react-start";
import { getRequestHeader, getRequestIP } from "@tanstack/react-start/server";
import { z } from "zod";

import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { LAB_SCENARIOS } from "./security-lab";

const runSchema = z.object({
  scenario: z.enum(LAB_SCENARIOS),
  transferId: z.string().uuid().nullish(),
});

const incidentSchema = z.object({ incidentId: z.string().uuid() });

function ip(): string {
  return getRequestIP({ xForwardedFor: true }) ?? getRequestHeader("x-forwarded-for") ?? "unknown";
}

function ua(): string {
  return getRequestHeader("user-agent") ?? "unknown";
}

export const labOverview = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getAdmin } = await import("./security.server");
    const { provisionLab, listLabTransfers } = await import("./security-lab.server");
    const admin = await getAdmin();
    const users = await provisionLab(admin);
    const transfers = await listLabTransfers(admin, context.userId);
    return { users, transfers };
  });

export const runLabScenarioFn = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => runSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin } = await import("./security.server");
    const { runLabScenario } = await import("./security-lab.server");
    const admin = await getAdmin();
    return runLabScenario(admin, {
      scenario: data.scenario,
      ownerId: context.userId,
      ip: ip(),
      userAgent: ua(),
      transferId: data.transferId ?? null,
    });
  });

export const incidentDetail = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => incidentSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin } = await import("./security.server");
    const { getIncidentDetail } = await import("./security-lab.server");
    const admin = await getAdmin();
    return getIncidentDetail(admin, data.incidentId, context.userId);
  });

export const labDashboard = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { getAdmin } = await import("./security.server");
    const { labDashboardData } = await import("./security-lab.server");
    const admin = await getAdmin();
    return labDashboardData(admin, context.userId);
  });

const decisionSchema = z.object({
  incidentId: z.string().uuid(),
  decision: z.enum(["CONFIRMED", "DENIED"]),
});

export const receiverDecision = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((d: unknown) => decisionSchema.parse(d))
  .handler(async ({ data, context }) => {
    const { getAdmin } = await import("./security.server");
    const { applyReceiverDecision } = await import("./security-lab.server");
    const admin = await getAdmin();
    return applyReceiverDecision(admin, {
      incidentId: data.incidentId,
      decision: data.decision,
      ownerId: context.userId,
      ip: ip(),
    });
  });
