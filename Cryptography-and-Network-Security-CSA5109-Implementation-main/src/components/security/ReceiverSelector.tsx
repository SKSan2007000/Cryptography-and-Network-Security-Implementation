import { useQuery } from "@tanstack/react-query";
import { KeyRound, ShieldAlert, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { supabase } from "@/integrations/supabase/client";
import { getTrustStatus, type TrustStatus } from "@/lib/security-rules";
import { cn } from "@/lib/utils";

export type Receiver = {
  id: string;
  email: string;
  full_name: string | null;
  trust_score: number;
  trust_status?: string;
  status: string;
  hasKey: boolean;
};

export function useReceivers(currentUserId: string | undefined) {
  return useQuery({
    queryKey: ["receivers", currentUserId],
    enabled: Boolean(currentUserId),
    queryFn: async (): Promise<Receiver[]> => {
      // Key material is never readable across accounts; only the list of
      // accounts that have published a public key is exposed.
      const [{ data: profiles }, { data: keys }] = await Promise.all([
        supabase.from("profiles").select("id, email, full_name, trust_score, trust_status, status"),
        supabase.rpc("users_with_published_keys"),
      ]);
      const keyed = new Set((keys ?? []).map((k) => k.user_id));
      return (profiles ?? [])
        .filter((p) => p.id !== currentUserId)
        .map((p) => ({ ...p, hasKey: keyed.has(p.id) }));
    },
  });
}

export function ReceiverSelector({
  currentUserId,
  value,
  onChange,
  onSelectReceiver,
  disabled,
}: {
  currentUserId: string | undefined;
  value: string | null;
  onChange: (id: string) => void;
  onSelectReceiver?: (receiver: Receiver | null) => void;
  disabled?: boolean;
}) {
  const { data, isLoading } = useReceivers(currentUserId);

  if (isLoading) return <Skeleton className="h-10 w-full" />;

  const receivers = data ?? [];
  if (receivers.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-4 text-sm text-muted-foreground">
        No other registered accounts yet. Register a second account to demonstrate a transfer.
      </div>
    );
  }

  const selected = receivers.find((r) => r.id === value) ?? null;

  const handleValueChange = (id: string) => {
    onChange(id);
    const rec = receivers.find((r) => r.id === id) ?? null;
    onSelectReceiver?.(rec);
  };

  return (
    <div className="space-y-2">
      <Label htmlFor="receiver">Authenticated receiver</Label>
      <Select
        {...(value ? { value } : {})}
        onValueChange={handleValueChange}
        disabled={disabled ?? false}
      >
        <SelectTrigger id="receiver">
          <SelectValue placeholder="Select a verified recipient" />
        </SelectTrigger>
        <SelectContent>
          {receivers.map((r) => {
            const score = r.trust_score ?? 100;
            const status: TrustStatus = getTrustStatus(score);
            const isHighRisk = score < 60;
            return (
              <SelectItem key={r.id} value={r.id} disabled={!r.hasKey || r.status !== "active"}>
                <div className="flex items-center justify-between gap-3 w-full">
                  <span className="font-medium">{r.full_name ?? r.email}</span>
                  <div className="flex items-center gap-1.5 text-xs">
                    <span className="mono">trust {score}</span>
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] px-1.5 py-0",
                        status === "TRUSTED" && "border-secure/50 text-secure",
                        status === "NORMAL" && "border-primary/50 text-primary",
                        status === "CAUTION" && "border-warning/50 text-warning",
                        status === "HIGH RISK" && "border-critical/50 text-critical",
                      )}
                    >
                      {status}
                    </Badge>
                    {!r.hasKey ? <span className="text-[10px] text-warning">· no key</span> : null}
                  </div>
                </div>
              </SelectItem>
            );
          })}
        </SelectContent>
      </Select>
      {selected ? (
        <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
          <p className="flex items-center gap-1.5">
            {selected.hasKey ? (
              <>
                <KeyRound className="size-3.5 text-secure" /> RSA-OAEP 2048 public key published
              </>
            ) : (
              <>
                <ShieldAlert className="size-3.5 text-warning" /> Recipient must publish a key first
              </>
            )}
          </p>
        </div>
      ) : null}
    </div>
  );
}
