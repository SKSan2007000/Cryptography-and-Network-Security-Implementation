import { format } from "date-fns";

import { ThreatLevelBadge } from "./ThreatLevelBadge";
import { cn } from "@/lib/utils";

export type TimelineEvent = {
  id: string;
  event: string;
  severity: string;
  created_at: string;
  action?: string | null;
  simulated?: boolean;
};

export function SecurityTimeline({
  events,
  className,
  emptyLabel = "No security events recorded yet.",
}: {
  events: TimelineEvent[];
  className?: string;
  emptyLabel?: string;
}) {
  if (events.length === 0) {
    return <p className={cn("text-sm text-muted-foreground", className)}>{emptyLabel}</p>;
  }
  return (
    <ol className={cn("relative space-y-4 border-l border-border pl-5", className)}>
      {events.map((e) => (
        <li key={e.id} className="relative">
          <span
            className={cn(
              "absolute -left-[1.4rem] top-1.5 size-2 rounded-full",
              e.severity === "critical" || e.severity === "high"
                ? "bg-critical"
                : e.severity === "medium"
                  ? "bg-warning"
                  : "bg-secure",
            )}
          />
          <div className="flex flex-wrap items-center gap-2">
            <span className="mono text-sm">{e.event}</span>
            <ThreatLevelBadge level={e.severity} />
            {e.simulated ? <ThreatLevelBadge level="medium" label="DEMO SIMULATION" /> : null}
          </div>
          <p className="text-xs text-muted-foreground">
            {format(new Date(e.created_at), "dd MMM yyyy HH:mm:ss")}
            {e.action ? ` · ${e.action.replace(/_/g, " ").toLowerCase()}` : ""}
          </p>
        </li>
      ))}
    </ol>
  );
}
