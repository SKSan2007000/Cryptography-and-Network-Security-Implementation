import { KeyRound, Lock, Fingerprint } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";

const ITEMS = [
  { icon: Lock, title: "AES-256-GCM", subtitle: "Per-transfer random key + 96-bit IV" },
  { icon: KeyRound, title: "RSA-OAEP 2048", subtitle: "SHA-256 key wrapping for the receiver" },
  { icon: Fingerprint, title: "SHA-256", subtitle: "File fingerprint for integrity proof" },
];

export function EncryptionStatus({
  active = true,
  className,
}: {
  active?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("grid gap-3 sm:grid-cols-3", className)}>
      {ITEMS.map(({ icon: Icon, title, subtitle }) => (
        <Card key={title} className="panel">
          <CardContent className="flex items-start gap-3 p-4">
            <span
              className={cn(
                "rounded-md p-2",
                active ? "bg-secure/10 text-secure" : "bg-muted text-muted-foreground",
              )}
            >
              <Icon className="size-4" />
            </span>
            <div className="min-w-0">
              <p className="text-sm font-semibold">{title}</p>
              <p className="text-xs text-muted-foreground">{subtitle}</p>
              <p
                className={cn(
                  "mt-1 text-[11px] font-medium uppercase tracking-wider",
                  active ? "text-secure" : "text-muted-foreground",
                )}
              >
                {active ? "Active" : "Idle"}
              </p>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
