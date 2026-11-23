import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Activity, FileLock2, Globe, ShieldAlert, Users } from "lucide-react";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { PerformanceChart } from "@/components/security/PerformanceChart";
import { StatCard } from "@/components/security/StatCard";
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { adminOverview } from "@/lib/sentinel.functions";

export const Route = createFileRoute("/_authenticated/admin/")({
  head: () => ({
    meta: [
      { title: "Admin Dashboard — SentinelCrypt" },
      {
        name: "description",
        content: "Platform-wide users, transfers, threats and performance overview.",
      },
    ],
  }),
  component: AdminDashboard,
});

export function useAdminOverview() {
  return useQuery({
    queryKey: ["admin-overview"],
    queryFn: () => adminOverview(),
  });
}

function AdminDashboard() {
  const overview = useAdminOverview();

  if (overview.isLoading) {
    return (
      <AppShell title="Admin Dashboard">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      </AppShell>
    );
  }

  const data = overview.data;
  if (!data) {
    return (
      <AppShell title="Admin Dashboard">
        <p className="text-sm text-critical">Administrator role required to view this data.</p>
      </AppShell>
    );
  }

  const blocked = data.incidents.filter((i) => i.blocked).length;

  return (
    <AppShell
      title="Admin Dashboard"
      description="Platform-wide security and performance overview."
      actions={
        <Link to="/digital-twin">
          <Button
            variant="outline"
            size="sm"
            className="gap-2 border-primary/40 text-primary hover:bg-primary/10"
          >
            <Globe className="size-4" /> Open Digital Twin
          </Button>
        </Link>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Users" value={data.users.length} icon={Users} />
        <StatCard label="Transfers" value={data.transfers.length} icon={FileLock2} />
        <StatCard
          label="Threats (blocked)"
          value={`${data.incidents.length} (${blocked})`}
          icon={ShieldAlert}
          tone="critical"
        />
        <StatCard
          label="Active Sessions"
          value={data.activeSessions}
          icon={Activity}
          tone="secure"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Average Pipeline Timings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <PerformanceChart
              data={[
                { name: "hash", ms: data.averages.hashingMs },
                { name: "encrypt", ms: data.averages.encryptionMs },
                { name: "upload", ms: data.averages.transferMs },
                { name: "verify", ms: data.averages.verificationMs },
              ]}
            />
          </CardContent>
        </Card>

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Recent Incidents
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {data.incidents.length === 0 ? (
              <p className="text-sm text-muted-foreground">No incidents across the platform.</p>
            ) : (
              data.incidents.slice(0, 8).map((i) => (
                <div
                  key={i.id}
                  className="flex items-center justify-between gap-2 rounded-md border border-border p-2.5"
                >
                  <p className="mono text-xs">
                    {i.threat_type.replace(/_/g, " ")}
                    {i.simulated ? " (demo)" : ""}
                  </p>
                  <ThreatLevelBadge level={i.severity} />
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
