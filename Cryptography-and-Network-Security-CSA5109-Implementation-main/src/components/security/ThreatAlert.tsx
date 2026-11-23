import { ShieldAlert } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { ThreatLevelBadge } from "./ThreatLevelBadge";
import { cn } from "@/lib/utils";

export type ThreatSummary = {
  label: string;
  severity: string;
  action: string;
  trustDelta: number;
  simulated?: boolean;
  description?: string;
};

export function ThreatAlert({ threat, className }: { threat: ThreatSummary; className?: string }) {
  return (
    <Alert
      className={cn(
        "border-critical/40 bg-critical/5",
        threat.simulated && "border-warning/40 bg-warning/5",
        className,
      )}
    >
      <ShieldAlert className={cn("size-4", threat.simulated ? "text-warning" : "text-critical")} />
      <AlertTitle className="flex flex-wrap items-center gap-2">
        {threat.simulated ? <ThreatLevelBadge level="medium" label="DEMO SIMULATION" /> : null}
        {threat.label}
        <ThreatLevelBadge level={threat.severity} className="ml-auto" />
      </AlertTitle>
      <AlertDescription className="space-y-1 text-sm">
        {threat.description ? <p>{threat.description}</p> : null}
        <p className="mono text-xs text-muted-foreground">
          response: {threat.action.replace(/_/g, " ").toLowerCase()} · trust {threat.trustDelta}
        </p>
      </AlertDescription>
    </Alert>
  );
}
