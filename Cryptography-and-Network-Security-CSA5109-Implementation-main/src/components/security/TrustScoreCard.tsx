import { ShieldCheck } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ThreatLevelBadge } from "./ThreatLevelBadge";
import { getTrustStatus, type TrustStatus } from "@/lib/security-rules";
import { cn } from "@/lib/utils";

export type TrustReason = {
  id: string;
  event_type: string;
  trust_delta: number;
  created_at: string;
  simulated?: boolean;
};

function bandLevel(score: number): "secure" | "low" | "medium" | "critical" {
  if (score >= 90) return "secure";
  if (score >= 75) return "low";
  if (score >= 60) return "medium";
  return "critical";
}

export function TrustScoreCard({
  score,
  reasons = [],
  className,
}: {
  score: number;
  reasons?: TrustReason[];
  className?: string;
}) {
  const deductions = reasons.filter((r) => r.trust_delta !== 0).slice(0, 5);
  const status: TrustStatus = getTrustStatus(score);
  return (
    <Card className={cn("panel", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
          <ShieldCheck className="size-4 text-primary" /> Trust Score
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-end gap-3">
          <span className="mono text-4xl font-semibold tabular-nums">{score}</span>
          <span className="pb-1 text-sm text-muted-foreground">/ 100</span>
          <ThreatLevelBadge level={bandLevel(score)} label={status} className="mb-1.5 ml-auto" />
        </div>
        <Progress value={score} className="h-1.5" />
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-muted-foreground">Why this score changed</p>
          {deductions.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              No deductions recorded. Score starts at 100 and only changes from detected events.
            </p>
          ) : (
            <ul className="space-y-1">
              {deductions.map((r) => (
                <li key={r.id} className="flex items-center justify-between text-xs">
                  <span className="truncate text-foreground/80">
                    {r.event_type.replace(/_/g, " ").toLowerCase()}
                    {r.simulated ? " (demo)" : ""}
                  </span>
                  <span className="mono text-critical">{r.trust_delta}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
