import { createFileRoute, Link } from "@tanstack/react-router";
import { Ban, CheckCircle2, FileLock2, Hourglass, ShieldAlert, UploadCloud } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { EmptyState, StatCard } from "@/components/security/StatCard";
import { SecurityTimeline } from "@/components/security/SecurityTimeline";
import { TransferCard } from "@/components/security/TransferCard";
import { TrustScoreCard } from "@/components/security/TrustScoreCard";
import { useAuth } from "@/hooks/useAuth";
import { firstFile, useAuditLogs, useSecurityEvents, useTransfers } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/dashboard")({
  head: () => ({
    meta: [
      { title: "Dashboard — SentinelCrypt" },
      {
        name: "description",
        content:
          "SentinelCrypt security dashboard with live transfer metrics, trust score and threat overview.",
      },
    ],
  }),
  component: DashboardPage,
});

const ACTIVE_STATES = new Set(["CREATED", "ENCRYPTING", "ENCRYPTED", "TRANSFERRING", "VERIFYING"]);

function DashboardPage() {
  const { user, profile } = useAuth();
  const transfers = useTransfers(user?.id, "all");
  const events = useSecurityEvents(50);
  const audit = useAuditLogs({ limit: 40 });

  const all = transfers.data ?? [];
  const active = all.filter((t) => ACTIVE_STATES.has(t.status));
  const completed = all.filter((t) => t.status === "COMPLETED");
  const recent = all.slice(0, 5);

  const evts = events.data ?? [];
  const threatsDetected = evts.length;
  const threatsBlocked = evts.filter(
    (e) => e.severity === "high" || e.severity === "critical",
  ).length;
  const integrityFailures = evts.filter((e) => e.event_type === "INTEGRITY_FAILURE").length;

  const byDay = new Map<string, number>();
  for (const t of all) {
    const day = t.created_at.slice(0, 10);
    byDay.set(day, (byDay.get(day) ?? 0) + 1);
  }
  const volume = Array.from(byDay.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-10)
    .map(([day, count]) => ({ name: day.slice(5), count }));

  return (
    <AppShell
      title="Security Dashboard"
      description="Live view of your transfers, trust score and detected threats."
      actions={
        <Button asChild>
          <Link to="/send">
            <UploadCloud className="mr-2 size-4" /> New secure transfer
          </Link>
        </Button>
      }
    >
      {transfers.isLoading || events.isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      ) : transfers.isError || events.isError ? (
        <EmptyState
          icon={ShieldAlert}
          title="Dashboard data unavailable"
          description="Your transfer metrics could not be loaded. Please retry in a moment."
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <StatCard label="Total Transfers" value={all.length} icon={FileLock2} />
          <StatCard
            label="Active Transfers"
            value={active.length}
            icon={Hourglass}
            hint="in progress"
          />
          <StatCard label="Completed" value={completed.length} icon={CheckCircle2} tone="secure" />
          <StatCard
            label="Threats Detected"
            value={threatsDetected}
            icon={ShieldAlert}
            tone="warning"
          />
          <StatCard label="Threats Blocked" value={threatsBlocked} icon={Ban} tone="critical" />
          <StatCard
            label="Integrity Failures"
            value={integrityFailures}
            icon={FileLock2}
            tone="critical"
          />
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-3">
        <TrustScoreCard
          score={profile?.trust_score ?? 100}
          reasons={evts.map((e) => ({
            id: e.id,
            event_type: e.event_type,
            trust_delta: e.trust_delta,
            created_at: e.created_at,
            simulated: e.simulated,
          }))}
        />

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Active Transfers
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {active.length === 0 ? (
              <p className="text-sm text-muted-foreground">No transfers in progress right now.</p>
            ) : (
              active
                .slice(0, 3)
                .map((t) => (
                  <TransferCard
                    key={t.id}
                    transfer={{ ...t, file_metadata: firstFile(t) }}
                    direction={t.sender_id === user?.id ? "sent" : "received"}
                  />
                ))
            )}
          </CardContent>
        </Card>

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Transfer Analytics
            </CardTitle>
          </CardHeader>
          <CardContent>
            {volume.length === 0 ? (
              <p className="text-sm text-muted-foreground">No transfer volume yet.</p>
            ) : (
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={volume}>
                    <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
                    <XAxis
                      dataKey="name"
                      tick={{ fontSize: 10 }}
                      stroke="var(--color-muted-foreground)"
                    />
                    <YAxis
                      allowDecimals={false}
                      tick={{ fontSize: 10 }}
                      stroke="var(--color-muted-foreground)"
                    />
                    <Tooltip
                      contentStyle={{
                        background: "var(--color-card)",
                        border: "1px solid var(--color-border)",
                        borderRadius: "0.5rem",
                        fontSize: 12,
                      }}
                    />
                    <Bar dataKey="count" fill="var(--color-chart-1)" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Recent Transfers
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {recent.length === 0 ? (
              <EmptyState
                icon={FileLock2}
                title="No transfers yet"
                description="Create your first encrypted transfer to see it here."
                action={
                  <Button asChild size="sm">
                    <Link to="/send">New transfer</Link>
                  </Button>
                }
              />
            ) : (
              recent.map((t) => (
                <TransferCard
                  key={t.id}
                  transfer={{ ...t, file_metadata: firstFile(t) }}
                  direction={t.sender_id === user?.id ? "sent" : "received"}
                />
              ))
            )}
          </CardContent>
        </Card>

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Security Events
            </CardTitle>
          </CardHeader>
          <CardContent>
            <SecurityTimeline
              events={(audit.data ?? []).slice(0, 12)}
              emptyLabel="No security events recorded yet."
            />
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
