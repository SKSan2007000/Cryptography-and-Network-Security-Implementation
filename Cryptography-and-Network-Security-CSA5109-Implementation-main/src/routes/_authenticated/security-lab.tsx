import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute } from "@tanstack/react-router";
import {
  AlertTriangle,
  Ban,
  Fingerprint,
  FlaskConical,
  Loader2,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import {
  IncidentAlertOverlay,
  type IncidentAlertData,
} from "@/components/security/IncidentAlertOverlay";
import { IncidentTimelinePanel } from "@/components/security/IncidentTimelinePanel";
import { ReceiverConfirmation } from "@/components/security/ReceiverConfirmation";
import { ThreatIntelPanel } from "@/components/security/ThreatIntelPanel";
import { SecurityTimeline } from "@/components/security/SecurityTimeline";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { useAuth } from "@/hooks/useAuth";
import {
  LAB_SCENARIOS,
  LAB_SCENARIO_SPECS,
  SOURCE_EVIDENCE_DISCLAIMER,
  type LabDashboard,
  type LabRunResult,
  type LabScenario,
} from "@/lib/security-lab";
import {
  incidentDetail,
  labDashboard,
  labOverview,
  runLabScenarioFn,
} from "@/lib/security-lab.functions";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/security-lab")({
  head: () => ({
    meta: [
      { title: "Controlled Security Testing Lab — SentinelCrypt" },
      {
        name: "description",
        content:
          "Run controlled security scenarios against dedicated test transfers and observe detection, trust evaluation, blocking, notification and audit response.",
      },
      { property: "og:title", content: "Controlled Security Testing Lab — SentinelCrypt" },
      {
        property: "og:description",
        content:
          "Controlled defensive testing environment for SentinelCrypt: detection, trust evaluation and automatic threat response.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: SecurityLabPage,
});

function Metric({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: string | undefined;
}) {
  return (
    <div className="rounded-md border border-border p-3">
      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn("mt-1 text-sm font-semibold", tone)}>{value}</p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="mono break-all text-right text-[11px]">{value}</span>
    </div>
  );
}

function IncidentInvestigation({ incidentId }: { incidentId: string }) {
  const query = useQuery({
    queryKey: ["incident", incidentId],
    queryFn: () => incidentDetail({ data: { incidentId } }),
  });

  if (query.isLoading)
    return <p className="text-xs text-muted-foreground">Loading incident record…</p>;
  const detail = query.data;
  if (!detail) return <p className="text-xs text-muted-foreground">Incident not available.</p>;

  const inc = detail.incident;
  return (
    <div className="space-y-2">
      <Row label="Incident ID" value={inc.id} />
      <Row label="Transfer ID" value={inc.transfer_id ?? "—"} />
      <Row label="Threat type" value={inc.threat_type} />
      <Row label="Severity" value={inc.severity.toUpperCase()} />
      <Row label="Response action" value={inc.action_taken} />
      <Row label="Access" value={inc.blocked ? "BLOCKED" : "RECORDED"} />
      <Row label="Transfer status" value={detail.transfer?.status ?? "—"} />
      <Row label="Recorded at" value={new Date(inc.created_at).toLocaleString()} />
      <Row label="Notifications" value={`${detail.notifications.length} created`} />
      <Row label="Audit entries" value={`${detail.audit.length} recorded`} />
    </div>
  );
}

function ResultPanel({ result }: { result: LabRunResult }) {
  const blocked = result.blocked;
  return (
    <div className="space-y-4">
      <div
        className={cn(
          "rounded-md border p-4",
          blocked ? "border-destructive/50 bg-destructive/10" : "border-warning/50 bg-warning/10",
        )}
      >
        <p className="flex items-center gap-2 text-sm font-semibold">
          {blocked ? (
            <Ban className="size-4 text-destructive" />
          ) : (
            <AlertTriangle className="size-4 text-warning" />
          )}
          {result.title} — {blocked ? "ACCESS BLOCKED" : "ANOMALY RECORDED"}
        </p>
        <p className="mt-1 text-xs text-muted-foreground">{result.outcome}</p>
      </div>

      <div className="grid gap-2 sm:grid-cols-4">
        <Metric label="Trust before" value={`${result.trustBefore} / 100`} />
        <Metric
          label="Trust after"
          value={`${result.trustAfter} / 100`}
          tone={result.trustAfter < result.trustBefore ? "text-destructive" : undefined}
        />
        <Metric label="Status before" value={result.transferStatusBefore} />
        <Metric
          label="Status after"
          value={result.transferStatusAfter}
          tone={
            result.transferStatusAfter !== result.transferStatusBefore
              ? "text-destructive"
              : undefined
          }
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Fingerprint className="size-4" /> Observed source evidence
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Row label="Test account" value={result.evidence.actorLabel} />
            <Row label="Account ID" value={result.evidence.actorId} />
            <Row label="Session ID" value={result.evidence.sessionId ?? "—"} />
            <Row label="Device ID" value={result.evidence.deviceId ?? "—"} />
            <Row label="Device fingerprint" value={result.evidence.deviceFingerprint} />
            <Row label="IP address" value={result.evidence.ipAddress ?? "not available"} />
            <Row label="User agent" value={result.evidence.userAgent ?? "not available"} />
            <Row label="Transfer ID" value={result.evidence.transferId} />
            <Row label="Attempts" value={String(result.evidence.attemptCount)} />
            <Row label="Timestamp" value={new Date(result.evidence.timestamp).toLocaleString()} />
            <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">
              {SOURCE_EVIDENCE_DISCLAIMER}
            </p>
          </CardContent>
        </Card>

        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <ShieldAlert className="size-4" /> Automatic response
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            <Row label="Detection stage" value={result.stage ?? "—"} />
            <Row label="Threat type" value={result.threatType ?? "—"} />
            <Row label="Severity" value={(result.severity ?? "—").toUpperCase()} />
            <Row label="Response action" value={result.responseAction ?? "—"} />
            <Separator className="my-2" />
            {result.notifications.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                No notification was configured for this rule.
              </p>
            ) : (
              result.notifications.map((n, i) => (
                <Row
                  key={i}
                  label={n.role === "sender" ? "Sender notified" : "Receiver notified"}
                  value={n.title}
                />
              ))
            )}
            <Separator className="my-2" />
            {result.incidentId ? (
              <IncidentInvestigation incidentId={result.incidentId} />
            ) : (
              <p className="text-xs text-muted-foreground">No threat incident recorded.</p>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <ThreatIntelPanel intel={result.intel} />
        <IncidentTimelinePanel entries={result.timeline} />
      </div>

      {result.receiverConfirmationRequired && result.incidentId ? (
        <ReceiverConfirmation
          incidentId={result.incidentId}
          fileName={result.fileName}
          senderLabel="You (lab sender account)"
        />
      ) : null}

      {result.integrity ? (
        <Card className="panel border-destructive/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">SHA-256 integrity comparison</CardTitle>
            <CardDescription>
              Fingerprint recorded for the authenticated AES-256-GCM ciphertext versus the
              fingerprint recomputed over the stored bytes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Row label="Expected SHA-256" value={result.integrity.expectedSha256} />
            <Row label="Computed SHA-256" value={result.integrity.computedSha256} />
            <Row label="Match" value={String(result.integrity.match)} />
            <Row
              label="AES-GCM authentication"
              value={result.integrity.gcmAuthenticated ? "would succeed" : "would fail"}
            />
          </CardContent>
        </Card>
      ) : null}

      <Card className="panel">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm">Audit events recorded by this run</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-1.5">
          {result.auditEvents.length === 0 ? (
            <p className="text-xs text-muted-foreground">No audit events.</p>
          ) : (
            result.auditEvents.map((e, i) => (
              <Badge key={`${e}-${i}`} variant="outline" className="mono text-[10px]">
                {e}
              </Badge>
            ))
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function SecurityLabPage() {
  const { refreshProfile } = useAuth();
  const queryClient = useQueryClient();
  const [scenario, setScenario] = useState<LabScenario>("INVALID_TOKEN");
  const [transferId, setTransferId] = useState<string>("new");
  const [result, setResult] = useState<LabRunResult | null>(null);
  const [alert, setAlert] = useState<IncidentAlertData | null>(null);
  const [alertOpen, setAlertOpen] = useState(false);

  const overview = useQuery({ queryKey: ["lab-overview"], queryFn: () => labOverview() });
  const dashboard = useQuery({ queryKey: ["lab-dashboard"], queryFn: () => labDashboard() });

  const spec = LAB_SCENARIO_SPECS[scenario];
  const forcesFresh = spec.requiresFreshTransfer;

  const run = useMutation({
    mutationFn: () =>
      runLabScenarioFn({
        data: {
          scenario,
          transferId: forcesFresh || transferId === "new" ? null : transferId,
        },
      }),
    onSuccess: (data) => {
      setResult(data);
      if (data.threatType) {
        setAlert({
          eventId: data.incidentId ?? `${data.transferRef}-${Date.now()}`,
          transferRef: data.transferRef,

          fileName: data.fileName,
          threat: data.threatType,
          severity: data.severity ?? "medium",
          action: data.responseAction ?? "RECORDED",
          blocked: data.blocked,
          trustDelta: data.trustAfter - data.trustBefore,
          simulated: true,
        });
        setAlertOpen(true);
      }
      toast[data.blocked ? "error" : "warning"](
        `${data.title}: ${data.blocked ? "access blocked" : "anomaly recorded"}`,
      );
      void queryClient.invalidateQueries();
      void refreshProfile();
    },
    onError: (error) =>
      toast.error(error instanceof Error ? error.message : "Controlled test failed."),
  });

  return (
    <AppShell
      title="Controlled Security Testing Lab"
      description="Simulate controlled security events against test transfers and observe detection, trust evaluation, prevention, notification and audit response."
    >
      <IncidentAlertOverlay
        open={alertOpen}
        data={alert}
        onAcknowledge={() => setAlertOpen(false)}
        onViewDetails={() => {
          setAlertOpen(false);
          document.getElementById("lab-result")?.scrollIntoView({ behavior: "smooth" });
        }}
      />

      {dashboard.data ? <MonitoringDashboard data={dashboard.data} /> : null}

      <Card className="panel border-warning/30">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <FlaskConical className="size-4 text-warning" /> Defensive testing environment
          </CardTitle>
          <CardDescription>
            Scenarios run only against dedicated lab test transfers and lab test accounts, using the
            production download gate, threat engine and integrity verification. No external system
            is targeted and no production user file is modified.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-muted-foreground">Test transfer</p>
              <Select
                value={forcesFresh ? "new" : transferId}
                onValueChange={setTransferId}
                disabled={forcesFresh}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select test transfer" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="new">New lab test transfer (provisioned on launch)</SelectItem>
                  {(overview.data?.transfers ?? []).map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.id.slice(0, 8)} · {t.status}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {forcesFresh ? (
                <p className="text-[11px] text-muted-foreground">
                  This scenario needs the one-time token, so a fresh test transfer is provisioned.
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <p className="text-xs font-medium text-muted-foreground">Test accounts</p>
              <div className="rounded-md border border-border p-2.5 text-[11px]">
                <p className="mono">{overview.data?.users.receiver.email ?? "provisioning…"}</p>
                <p className="text-muted-foreground">Authorized test receiver</p>
                <p className="mono mt-1.5">{overview.data?.users.attacker.email ?? ""}</p>
                <p className="text-muted-foreground">Unauthorized test user</p>
              </div>
            </div>
          </div>

          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {LAB_SCENARIOS.map((id) => {
              const s = LAB_SCENARIO_SPECS[id];
              const active = id === scenario;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setScenario(id)}
                  className={cn(
                    "rounded-md border p-3 text-left transition-colors",
                    active
                      ? "border-primary bg-primary/10"
                      : "border-border hover:border-primary/40",
                  )}
                >
                  <p className="text-xs font-semibold">{s.title}</p>
                  <p className="mt-1 text-[11px] leading-snug text-muted-foreground">{s.summary}</p>
                  <p className="mono mt-1.5 text-[10px] text-muted-foreground">{s.executes}</p>
                </button>
              );
            })}
          </div>

          <Button
            onClick={() => run.mutate()}
            disabled={run.isPending}
            variant="destructive"
            className="w-full sm:w-auto"
          >
            {run.isPending ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
            Launch controlled test
          </Button>
        </CardContent>
      </Card>

      <div id="lab-result">
        {result ? (
          <ResultPanel result={result} />
        ) : (
          <Card className="panel">
            <CardContent className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
              <ShieldCheck className="size-4" /> Select a scenario and launch a controlled test to
              see detection, trust evaluation, blocking, notification and audit evidence.
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}

function MonitoringDashboard({ data }: { data: LabDashboard }) {
  const postureTone =
    data.posture === "SECURE"
      ? "text-secure"
      : data.posture === "ELEVATED RISK"
        ? "text-warning"
        : "text-critical";
  return (
    <div className="space-y-4">
      <Card className="panel">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldAlert className="size-4" /> Live security monitoring
          </CardTitle>
          <CardDescription>
            Real-time posture across your lab test estate, computed from persisted transfers,
            incidents and audit records.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-2 sm:grid-cols-3 lg:grid-cols-6">
            <Metric label="Security posture" value={data.posture} tone={postureTone} />
            <Metric label="Threat level" value={data.threatLevel} />
            <Metric label="Trust score" value={`${data.trustScore} / 100`} />
            <Metric label="Active transfers" value={String(data.activeTransfers)} />
            <Metric label="Open incidents" value={String(data.openIncidents)} />
            <Metric label="Blocked attempts" value={String(data.blockedAttempts)} />
          </div>

          {data.monitors.length > 0 ? (
            <div className="space-y-2">
              {data.monitors.map((m) => (
                <div
                  key={m.id}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-md border border-border p-3 text-xs"
                >
                  <Badge variant="outline" className="mono text-[10px]">
                    {m.ref}
                  </Badge>
                  <span className="mono">{m.fileName}</span>
                  <span className="text-muted-foreground">→ {m.receiverEmail}</span>
                  <Badge
                    variant="outline"
                    className={cn(
                      "text-[10px]",
                      m.status === "TERMINATED" && "border-destructive/50 text-destructive",
                    )}
                  >
                    {m.status}
                  </Badge>
                  <span className="text-muted-foreground">
                    downloads {m.downloadCount}/{m.maxDownloads}
                  </span>
                  <span className="ml-auto mono text-[10px] text-muted-foreground">
                    {m.lastEvent ?? "no activity"}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              No lab test transfers yet — launch a scenario to populate live monitoring.
            </p>
          )}

          <Separator />
          <SecurityTimeline events={data.recentEvents} emptyLabel="No recorded lab activity yet." />
        </CardContent>
      </Card>
    </div>
  );
}
