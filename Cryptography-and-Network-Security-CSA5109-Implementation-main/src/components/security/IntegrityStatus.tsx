import { BadgeCheck, ShieldX, Clock } from "lucide-react";

import { cn } from "@/lib/utils";

export function IntegrityStatus({
  state,
  expected,
  computed,
  className,
}: {
  state: "verified" | "failed" | "pending";
  expected?: string | null;
  computed?: string | null;
  className?: string;
}) {
  const config = {
    verified: {
      icon: BadgeCheck,
      text: "Integrity Verified",
      tone: "text-secure",
      bg: "bg-secure/10 border-secure/30",
    },
    failed: {
      icon: ShieldX,
      text: "Integrity Failed",
      tone: "text-critical",
      bg: "bg-critical/10 border-critical/30",
    },
    pending: {
      icon: Clock,
      text: "Awaiting verification",
      tone: "text-muted-foreground",
      bg: "bg-muted/40 border-border",
    },
  }[state];
  const Icon = config.icon;

  return (
    <div className={cn("rounded-lg border p-4", config.bg, className)}>
      <div className={cn("flex items-center gap-2 font-medium", config.tone)}>
        <Icon className="size-4" />
        {config.text}
      </div>
      <dl className="mt-3 space-y-1 text-[11px]">
        {expected ? (
          <div className="flex gap-2">
            <dt className="w-20 shrink-0 text-muted-foreground">expected</dt>
            <dd className="mono break-all">{expected}</dd>
          </div>
        ) : null}
        {computed ? (
          <div className="flex gap-2">
            <dt className="w-20 shrink-0 text-muted-foreground">computed</dt>
            <dd className="mono break-all">{computed}</dd>
          </div>
        ) : null}
      </dl>
    </div>
  );
}
