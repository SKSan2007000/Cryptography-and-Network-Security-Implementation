import { FlaskConical, Loader2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ThreatAlert, type ThreatSummary } from "./ThreatAlert";
import { THREAT_RULES, type ThreatType } from "@/lib/security-rules";
import { simulateThreat } from "@/lib/sentinel.functions";

const DEMO_THREATS: ThreatType[] = [
  "TOKEN_REPLAY",
  "INTEGRITY_FAILURE",
  "SUSPICIOUS_IP_CHANGE",
  "DEVICE_CHANGE",
  "CONCURRENT_SESSIONS",
  "EXCESSIVE_FAILED_DOWNLOADS",
  "ABNORMAL_REQUEST_RATE",
  "DOWNLOAD_LIMIT_EXCEEDED",
  "TRANSFER_EXPIRED",
  "EXPIRED_SESSION",
  "INVALID_TOKEN",
  "UNAUTHORIZED_RECEIVER",
];

export function SecurityDemo({
  transferId,
  onComplete,
}: {
  transferId?: string | null;
  onComplete?: () => void;
}) {
  const [running, setRunning] = useState<ThreatType | null>(null);
  const [last, setLast] = useState<ThreatSummary | null>(null);

  async function run(type: ThreatType) {
    setRunning(type);
    try {
      const threat = await simulateThreat({ data: { type, transferId: transferId ?? null } });
      setLast({ ...threat, simulated: true });
      toast.warning(
        `Simulated ${type.replace(/_/g, " ").toLowerCase()} — trust ${threat.trustDelta}`,
      );
      onComplete?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Simulation failed.");
    } finally {
      setRunning(null);
    }
  }

  return (
    <Card className="panel border-warning/30">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <FlaskConical className="size-4 text-warning" /> Security Demonstration Center
        </CardTitle>
        <CardDescription>
          Controlled security lab — every simulation runs through the production threat engine, is
          scored against your trust score, and is written to the audit log as DEMO SIMULATION.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {DEMO_THREATS.map((type) => {
            const rule = THREAT_RULES[type];
            return (
              <Button
                key={type}
                variant="outline"
                size="sm"
                className="h-auto flex-col items-start gap-0.5 whitespace-normal py-2 text-left"
                disabled={running !== null}
                onClick={() => void run(type)}
              >
                <span className="flex items-center gap-1.5 text-xs font-medium">
                  {running === type ? <Loader2 className="size-3 animate-spin" /> : null}
                  {rule.label}
                </span>
                <span className="mono text-[10px] text-muted-foreground">
                  severity {rule.severity} · trust {rule.trustDelta}
                </span>
              </Button>
            );
          })}
        </div>
        {last ? <ThreatAlert threat={last} /> : null}
      </CardContent>
    </Card>
  );
}
