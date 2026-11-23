import { cn } from "@/lib/utils";

const STATE_TONE: Record<string, string> = {
  CREATED: "bg-muted text-muted-foreground border-border",
  ENCRYPTING: "bg-info/10 text-info border-info/30",
  ENCRYPTED: "bg-info/10 text-info border-info/30",
  TRANSFERRING: "bg-info/10 text-info border-info/30",
  VERIFYING: "bg-warning/10 text-warning border-warning/30",
  COMPLETED: "bg-secure/10 text-secure border-secure/30",
  PAUSED: "bg-warning/10 text-warning border-warning/30",
  SUSPICIOUS: "bg-warning/15 text-warning border-warning/40",
  TERMINATED: "bg-critical/10 text-critical border-critical/40",
  EXPIRED: "bg-muted text-muted-foreground border-border",
  FAILED: "bg-critical/10 text-critical border-critical/40",
};

export function TransferStateBadge({ state, className }: { state: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider",
        STATE_TONE[state] ?? STATE_TONE["CREATED"],
        className,
      )}
    >
      {state}
    </span>
  );
}
