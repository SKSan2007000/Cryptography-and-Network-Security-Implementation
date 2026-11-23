import { format } from "date-fns";
import { Radio } from "lucide-react";

import { cn } from "@/lib/utils";
import { useAuth } from "@/hooks/useAuth";

export function SessionStatus({ className }: { className?: string }) {
  const { sessionInfo } = useAuth();
  const active = Boolean(sessionInfo?.sessionId);
  return (
    <div className={cn("flex items-center gap-2 text-xs", className)}>
      <Radio className={cn("size-3.5", active ? "text-secure" : "text-muted-foreground")} />
      <span className="text-muted-foreground">
        {active ? (
          <>
            Session monitored · expires{" "}
            <span className="mono">
              {sessionInfo?.expiresAt ? format(new Date(sessionInfo.expiresAt), "HH:mm") : "—"}
            </span>
            {sessionInfo?.ip ? <span className="mono"> · {sessionInfo.ip}</span> : null}
          </>
        ) : (
          "Establishing monitored session…"
        )}
      </span>
    </div>
  );
}
