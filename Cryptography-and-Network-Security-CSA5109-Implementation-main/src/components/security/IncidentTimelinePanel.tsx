import { format } from "date-fns";
import { History } from "lucide-react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { LabTimelineEntry } from "@/lib/security-lab-intel";

export function IncidentTimelinePanel({
  entries,
  title = "Incident timeline",
  description = "Every entry below is a persisted audit record — nothing is generated for display.",
}: {
  entries: LabTimelineEntry[];
  title?: string;
  description?: string;
}) {
  return (
    <Card className="panel">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <History className="size-4" /> {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        {entries.length === 0 ? (
          <p className="text-xs text-muted-foreground">No recorded events yet.</p>
        ) : (
          <ol className="relative space-y-3 border-l border-border pl-5">
            {entries.map((e, i) => (
              <li key={`${e.at}-${i}`} className="relative">
                <span className="absolute -left-[1.4rem] top-2 size-2 rounded-full bg-primary/70" />
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="mono text-[11px] text-muted-foreground">
                    {format(new Date(e.at), "HH:mm:ss")}
                  </span>
                  <span className="text-xs font-medium">{e.label}</span>
                </div>
                {e.detail ? <p className="text-[11px] text-muted-foreground">{e.detail}</p> : null}
              </li>
            ))}
          </ol>
        )}
      </CardContent>
    </Card>
  );
}
