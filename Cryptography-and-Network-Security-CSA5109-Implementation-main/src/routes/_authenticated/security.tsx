import { createFileRoute, Link } from "@tanstack/react-router";
import { KeyRound, MonitorSmartphone, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SecurityStatusCard, type SecurityRow } from "@/components/security/SecurityStatusCard";
import { SecurityTimeline } from "@/components/security/SecurityTimeline";
import { SessionStatus } from "@/components/security/SessionStatus";
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { TrustScoreCard } from "@/components/security/TrustScoreCard";
import { useAuth } from "@/hooks/useAuth";
import { getKeyRecord } from "@/lib/keyvault";
import {
  useAuditLogs,
  useDevices,
  useIncidents,
  useSecurityEvents,
  useSessions,
} from "@/lib/queries";
import { format } from "date-fns";

export const Route = createFileRoute("/_authenticated/security")({
  head: () => ({
    meta: [
      { title: "Security Center — SentinelCrypt" },
      {
        name: "description",
        content: "Trust score, threat incidents, sessions, devices and your cryptographic posture.",
      },
    ],
  }),
  component: SecurityCenterPage,
});

function SecurityCenterPage() {
  const { user, profile, sessionInfo } = useAuth();
  const events = useSecurityEvents(100);
  const incidents = useIncidents(50);
  const sessions = useSessions(user?.id);
  const devices = useDevices(user?.id);
  const audit = useAuditLogs({ limit: 30 });
  const [hasKeys, setHasKeys] = useState<boolean | null>(null);

  useEffect(() => {
    if (!user) return;
    void getKeyRecord(user.id).then((r) => setHasKeys(Boolean(r)));
  }, [user]);

  const score = profile?.trust_score ?? 100;
  const evts = events.data ?? [];
  const activeSessions = (sessions.data ?? []).filter(
    (s) => !s.revoked && new Date(s.expires_at).getTime() > Date.now(),
  );

  const posture: SecurityRow[] = [
    {
      label: "Transport encryption",
      value: "HTTPS / TLS",
      state: "ok",
      detail: "All traffic is encrypted in transit",
    },
    {
      label: "Client-side encryption",
      value: "AES-256-GCM",
      state: "ok",
      detail: "Files are encrypted before upload",
    },
    {
      label: "RSA key pair",
      value: hasKeys === null ? "checking…" : hasKeys ? "published" : "missing",
      state: hasKeys ? "ok" : "warn",
      detail: hasKeys
        ? "RSA-OAEP 2048 · private key wrapped with your key passphrase (PBKDF2)"
        : "Set up a key passphrase in Profile → Encryption Key Setup to receive files",
    },
    {
      label: "Monitored session",
      value: sessionInfo?.sessionId ? "active" : "starting",
      state: sessionInfo?.sessionId ? "ok" : "warn",
      ...(sessionInfo?.ip ? { detail: `IP ${sessionInfo.ip}` } : {}),
    },
    {
      label: "Account status",
      value: profile?.status ?? "active",
      state: profile?.status === "active" ? "ok" : "fail",
    },
  ];

  return (
    <AppShell
      title="Security Center"
      description="Your trust posture, threats, sessions and devices."
    >
      <SessionStatus />

      <div className="grid gap-4 lg:grid-cols-3">
        <TrustScoreCard
          score={score}
          reasons={evts.map((e) => ({
            id: e.id,
            event_type: e.event_type,
            trust_delta: e.trust_delta,
            created_at: e.created_at,
            simulated: e.simulated,
          }))}
        />
        <SecurityStatusCard title="Security posture" rows={posture} />
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <ShieldAlert className="size-4 text-warning" /> Threat Incidents
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(incidents.data ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No incidents recorded against your account.
              </p>
            ) : (
              (incidents.data ?? []).slice(0, 6).map((i) => (
                <div
                  key={i.id}
                  className="flex items-center justify-between gap-2 rounded-md border border-border p-2.5"
                >
                  <div className="min-w-0">
                    <p className="truncate text-xs font-medium">
                      {i.threat_type.replace(/_/g, " ")}
                      {i.simulated ? " (demo)" : ""}
                    </p>
                    <p className="mono text-[10px] text-muted-foreground">
                      {format(new Date(i.created_at), "dd MMM HH:mm")} · trust {i.trust_delta} ·{" "}
                      {i.blocked ? "blocked" : "logged"}
                    </p>
                  </div>
                  <ThreatLevelBadge level={i.severity} />
                </div>
              ))
            )}
            <Button variant="outline" size="sm" asChild className="w-full">
              <Link to="/demo">Open Security Lab</Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <MonitorSmartphone className="size-4" /> Sessions ({activeSessions.length} active)
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Started</TableHead>
                  <TableHead>IP</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>State</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(sessions.data ?? []).slice(0, 8).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="mono text-xs">
                      {format(new Date(s.created_at), "dd MMM HH:mm")}
                    </TableCell>
                    <TableCell className="mono text-xs">{s.ip_address ?? "—"}</TableCell>
                    <TableCell className="mono text-xs">
                      {format(new Date(s.expires_at), "HH:mm")}
                    </TableCell>
                    <TableCell>
                      <ThreatLevelBadge
                        level={s.revoked ? "critical" : "secure"}
                        label={s.revoked ? "REVOKED" : "ACTIVE"}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
              <KeyRound className="size-4" /> Known Devices
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(devices.data ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Devices are registered on first sign-in.
              </p>
            ) : (
              (devices.data ?? []).map((d) => (
                <div key={d.id} className="rounded-md border border-border p-2.5">
                  <p className="truncate text-xs font-medium">{d.user_agent ?? "Unknown device"}</p>
                  <p className="mono text-[10px] text-muted-foreground">
                    {d.fingerprint.slice(0, 18)}… · last seen{" "}
                    {format(new Date(d.last_seen), "dd MMM HH:mm")}
                  </p>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="panel">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium text-muted-foreground">
            Recent Security Events
          </CardTitle>
        </CardHeader>
        <CardContent>
          <SecurityTimeline events={audit.data ?? []} />
        </CardContent>
      </Card>
    </AppShell>
  );
}
