import { createFileRoute } from "@tanstack/react-router";
import { Send } from "lucide-react";
import { useMemo, useState } from "react";

import { AppShell } from "@/components/layout/AppShell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/security/StatCard";
import { TransferCard } from "@/components/security/TransferCard";
import { useAuth } from "@/hooks/useAuth";
import { firstFile, useProfileMap, useTransfers } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/sent")({
  head: () => ({
    meta: [
      { title: "Sent Files — SentinelCrypt" },
      {
        name: "description",
        content: "Track the status, integrity and expiry of every file you sent.",
      },
    ],
  }),
  component: SentPage,
});

const FILTERS = [
  { label: "All", value: "all" },
  { label: "In Transit", value: "ENCRYPTED" },
  { label: "Completed", value: "COMPLETED" },
  { label: "Expired", value: "EXPIRED" },
  { label: "Terminated", value: "TERMINATED" },
] as const;

function SentPage() {
  const { user } = useAuth();
  const transfers = useTransfers(user?.id, "sent");
  const profiles = useProfileMap();
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState("");

  const list = useMemo(() => {
    let rows = transfers.data ?? [];
    if (filter !== "all") rows = rows.filter((t) => t.status === filter);
    const q = query.trim().toLowerCase();
    if (q) {
      rows = rows.filter((t) => {
        const receiver = profiles.map.get(t.recipient_id);
        return (
          firstFile(t)?.original_name.toLowerCase().includes(q) ||
          (receiver?.full_name ?? receiver?.email ?? "").toLowerCase().includes(q)
        );
      });
    }
    return rows;
  }, [transfers.data, filter, query, profiles.map]);

  return (
    <AppShell
      title="Sent Files"
      description="Delivery status, integrity and expiry for your outgoing transfers."
    >
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search by file or receiver…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          className="w-full max-w-xs"
        />
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => setFilter(f.value)}
              className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                filter === f.value
                  ? "bg-primary text-primary-foreground"
                  : "bg-surface text-muted-foreground hover:text-foreground"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
      </div>

      {transfers.isLoading ? (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-36 w-full" />
          ))}
        </div>
      ) : list.length === 0 ? (
        <Card className="panel">
          <CardContent className="py-10">
            <EmptyState
              icon={Send}
              title="Nothing sent yet"
              description="Files you encrypt and send will be tracked here."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((t) => {
            const receiver = profiles.map.get(t.recipient_id);
            return (
              <TransferCard
                key={t.id}
                transfer={{
                  ...t,
                  file_metadata: firstFile(t),
                  counterpartyLabel: receiver?.full_name ?? receiver?.email ?? "Unknown receiver",
                }}
                direction="sent"
              />
            );
          })}
        </div>
      )}
    </AppShell>
  );
}
