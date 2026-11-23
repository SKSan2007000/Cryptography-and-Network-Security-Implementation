import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";

import { AppShell } from "@/components/layout/AppShell";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { AuditLogTable } from "@/components/security/AuditLogTable";
import { useAuditLogs } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/audit")({
  head: () => ({
    meta: [
      { title: "Audit Logs — SentinelCrypt" },
      {
        name: "description",
        content:
          "Immutable audit trail of logins, encryption steps, downloads and threat responses.",
      },
    ],
  }),
  component: AuditPage,
});

const SEVERITIES = ["all", "info", "low", "medium", "high", "critical"] as const;

function AuditPage() {
  const audit = useAuditLogs({ limit: 300 });
  const [severity, setSeverity] = useState<string>("all");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    let list = audit.data ?? [];
    if (severity !== "all") list = list.filter((r) => r.severity === severity);
    const q = query.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (r) =>
          r.event.toLowerCase().includes(q) ||
          (r.action ?? "").toLowerCase().includes(q) ||
          (r.ip_address ?? "").includes(q),
      );
    }
    return list;
  }, [audit.data, severity, query]);

  return (
    <AppShell
      title="Audit Logs"
      description="Every login, key operation, transfer step and threat response — immutable and timestamped."
    >
      <Card className="panel">
        <CardContent className="space-y-4 p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Input
              placeholder="Filter by event, action or IP…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full max-w-xs"
            />
            <div className="flex flex-wrap gap-1">
              {SEVERITIES.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSeverity(s)}
                  className={`rounded-md px-3 py-1.5 text-xs font-medium capitalize transition-colors ${
                    severity === s
                      ? "bg-primary text-primary-foreground"
                      : "bg-surface text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <AuditLogTable rows={rows} loading={audit.isLoading} />
        </CardContent>
      </Card>
    </AppShell>
  );
}
