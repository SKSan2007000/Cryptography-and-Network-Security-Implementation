import { Check, CircleDot, Circle, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import { isTerminal } from "@/lib/transfer-state";

type Stage = { label: string; events: string[] };

const STAGES: Stage[] = [
  { label: "Authentication verified", events: ["USER_LOGIN", "RECEIVER_ACCESS"] },
  { label: "File encrypted (AES-256-GCM)", events: ["ENCRYPTION_COMPLETED"] },
  { label: "AES key protected (RSA-OAEP)", events: ["KEY_WRAPPED"] },
  { label: "SHA-256 fingerprint generated", events: ["HASH_GENERATED"] },
  { label: "Secure transfer initiated", events: ["TRANSFER_STARTED", "TRANSFER_CREATED"] },
  { label: "Receiver authenticated", events: ["RECEIVER_ACCESS"] },
  { label: "Access token verified", events: ["TOKEN_VALIDATED"] },
  { label: "AES key recovered / payload fetched", events: ["DOWNLOAD_STARTED"] },
  { label: "File decrypted", events: ["DECRYPTION_COMPLETED"] },
  { label: "SHA-256 integrity verified", events: ["INTEGRITY_VERIFIED"] },
  { label: "Download completed", events: ["DOWNLOAD_COMPLETED"] },
];

const FAILURE_EVENTS = new Set([
  "INTEGRITY_FAILED",
  "DOWNLOAD_REJECTED",
  "INTEGRITY_REPORT_REJECTED",
]);

export function TransferLifecycle({
  events,
  status,
  className,
}: {
  events: { event: string }[];
  status: string;
  className?: string;
}) {
  const seen = new Set(events.map((e) => e.event));
  const failed = events.some((e) => FAILURE_EVENTS.has(e.event) || e.event.startsWith("THREAT_"));
  const halted = failed || ["TERMINATED", "SUSPICIOUS", "PAUSED", "FAILED"].includes(status);

  let activeAssigned = false;

  return (
    <ol className={cn("space-y-1.5", className)}>
      {STAGES.map((stage) => {
        const done = stage.events.some((e) => seen.has(e));
        const isActive = !done && !activeAssigned && !isTerminal(status);
        if (isActive) activeAssigned = true;
        const isFailed = !done && halted && !activeAssigned;
        return (
          <li key={stage.label} className="flex items-center gap-2 text-sm">
            {done ? (
              <Check className="size-4 shrink-0 text-secure" />
            ) : isActive && halted ? (
              <XCircle className="size-4 shrink-0 text-critical" />
            ) : isActive ? (
              <CircleDot className="size-4 shrink-0 animate-pulse text-primary" />
            ) : (
              <Circle className="size-4 shrink-0 text-muted-foreground/40" />
            )}
            <span
              className={cn(
                done && "text-foreground",
                !done && "text-muted-foreground",
                isActive && halted && "text-critical",
              )}
            >
              {stage.label}
              {isActive && !halted ? " — in progress" : ""}
            </span>
            {isFailed ? null : null}
          </li>
        );
      })}
    </ol>
  );
}
