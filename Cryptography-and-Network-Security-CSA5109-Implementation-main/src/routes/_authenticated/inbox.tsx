import { createFileRoute } from "@tanstack/react-router";
import { Inbox as InboxIcon } from "lucide-react";
import { useMemo, useState } from "react";

import { AppShell } from "@/components/layout/AppShell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState } from "@/components/security/StatCard";
import { TransferCard } from "@/components/security/TransferCard";
import { useAuth } from "@/hooks/useAuth";
import { isDownloadable } from "@/lib/transfer-state";
import { firstFile, useProfileMap, useTransfers } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/inbox")({
  head: () => ({
    meta: [
      { title: "Inbox — SentinelCrypt" },
      {
        name: "description",
        content: "Encrypted transfers sent to you, with verification and download controls.",
      },
    ],
  }),
  component: InboxPage,
});

const FILTERS = [
  { label: "All", value: "all" },
  { label: "Awaiting Download", value: "AWAITING" },
  { label: "Completed", value: "COMPLETED" },
  { label: "Expired", value: "EXPIRED" },
  { label: "Blocked", value: "TERMINATED" },
] as const;

function InboxPage() {
  const { user } = useAuth();
  const transfers = useTransfers(user?.id, "received");
  const profiles = useProfileMap();
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState("");

  const list = useMemo(() => {
    let rows = transfers.data ?? [];
    if (filter === "AWAITING") rows = rows.filter((t) => isDownloadable(t.status));
    else if (filter !== "all") rows = rows.filter((t) => t.status === filter);
    const q = query.trim().toLowerCase();
    if (q) {
      rows = rows.filter((t) => {
        const sender = profiles.map.get(t.sender_id);
        return (
          firstFile(t)?.original_name.toLowerCase().includes(q) ||
          (sender?.full_name ?? sender?.email ?? "").toLowerCase().includes(q)
        );
      });
    }
    return rows;
  }, [transfers.data, filter, query, profiles.map]);

  return (
    <AppShell title="Inbox" description="Files sent to you — verify integrity before downloading.">
      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Search by file or sender…"
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
              icon={InboxIcon}
              title="Your inbox is empty"
              description="When someone sends you an encrypted file it will appear here."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {list.map((t) => {
            const sender = profiles.map.get(t.sender_id);
            return (
              <TransferCard
                key={t.id}
                transfer={{
                  ...t,
                  file_metadata: firstFile(t),
                  counterpartyLabel: sender?.full_name ?? sender?.email ?? "Unknown sender",
                }}
                direction="received"
              />
            );
          })}
        </div>
      )}
    </AppShell>
  );
}
