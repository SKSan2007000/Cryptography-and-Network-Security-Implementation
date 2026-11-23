import { Check, X, AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export type SecurityRow = {
  label: string;
  value: string;
  state: "ok" | "warn" | "fail";
  detail?: string;
};

function Icon({ state }: { state: SecurityRow["state"] }) {
  if (state === "ok") return <Check className="size-3.5 text-secure" />;
  if (state === "warn") return <AlertTriangle className="size-3.5 text-warning" />;
  return <X className="size-3.5 text-critical" />;
}

export function SecurityStatusCard({
  title = "Security panel",
  rows,
  footer,
  className,
}: {
  title?: string;
  rows: SecurityRow[];
  footer?: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("panel", className)}>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {rows.map((row) => (
          <div
            key={row.label}
            className="flex items-start justify-between gap-3 border-b border-border/60 pb-2 last:border-0 last:pb-0"
          >
            <div>
              <p className="text-sm font-medium">{row.label}</p>
              {row.detail ? (
                <p className="mono text-[11px] text-muted-foreground">{row.detail}</p>
              ) : null}
            </div>
            <span
              className={cn(
                "flex shrink-0 items-center gap-1.5 text-xs font-medium",
                row.state === "ok" && "text-secure",
                row.state === "warn" && "text-warning",
                row.state === "fail" && "text-critical",
              )}
            >
              <Icon state={row.state} />
              {row.value}
            </span>
          </div>
        ))}
        {footer}
      </CardContent>
    </Card>
  );
}
