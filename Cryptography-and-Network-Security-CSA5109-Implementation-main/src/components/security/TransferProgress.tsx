import { Check, Loader2, Circle, XCircle } from "lucide-react";

import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";

export type Step = {
  key: string;
  label: string;
  status: "pending" | "active" | "done" | "failed";
  detail?: string;
};

export function TransferProgress({ steps, className }: { steps: Step[]; className?: string }) {
  const done = steps.filter((s) => s.status === "done").length;
  const pct = Math.round((done / steps.length) * 100);
  const failed = steps.some((s) => s.status === "failed");

  return (
    <div className={cn("space-y-3", className)}>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>Pipeline progress</span>
        <span className="mono">{failed ? "halted" : `${pct}%`}</span>
      </div>
      <Progress value={pct} className="h-1.5" />
      <ol className="space-y-2">
        {steps.map((step) => (
          <li key={step.key} className="flex items-center gap-2.5 text-sm">
            {step.status === "done" ? (
              <Check className="size-4 text-secure" />
            ) : step.status === "active" ? (
              <Loader2 className="size-4 animate-spin text-primary" />
            ) : step.status === "failed" ? (
              <XCircle className="size-4 text-critical" />
            ) : (
              <Circle className="size-4 text-muted-foreground/50" />
            )}
            <span
              className={cn(
                step.status === "pending" && "text-muted-foreground",
                step.status === "failed" && "text-critical",
              )}
            >
              {step.label}
            </span>
            {step.detail ? (
              <span className="mono ml-auto text-[11px] text-muted-foreground">{step.detail}</span>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  );
}
