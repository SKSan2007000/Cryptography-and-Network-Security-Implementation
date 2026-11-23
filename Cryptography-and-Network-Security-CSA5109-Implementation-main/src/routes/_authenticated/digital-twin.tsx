import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  Ban,
  CheckCircle2,
  Clock,
  ExternalLink,
  Eye,
  FileLock2,
  Fingerprint,
  Globe,
  HardDrive,
  KeyRound,
  Layers,
  MapPin,
  Maximize2,
  Radio,
  RefreshCw,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  User,
  Users,
} from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { DigitalTwinMap } from "@/components/security/DigitalTwinMap";
import { StatCard } from "@/components/security/StatCard";
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { getTrustStatus, type TrustStatus } from "@/lib/security-rules";
import { getDigitalTwinState } from "@/lib/sentinel.functions";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/digital-twin")({
  head: () => ({
    meta: [
      { title: "Security Digital Twin — SentinelCrypt" },
      {
        name: "description",
        content:
          "Live visual representation of the SentinelCrypt secure file-transfer ecosystem: user nodes, transfers, trust scores, cryptographic telemetry, and security events.",
      },
    ],
  }),
  component: DigitalTwinPage,
});

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function DigitalTwinPage() {
  const queryClient = useQueryClient();
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [selectedTransferId, setSelectedTransferId] = useState<string | null>(null);

  const { data, isLoading, isError, refetch, isFetching } = useQuery({
    queryKey: ["digital-twin-state"],
    queryFn: () => getDigitalTwinState(),
    refetchInterval: autoRefresh ? 6000 : false,
  });

  const summary = data?.summary;
  const userNodes = data?.userNodes ?? [];
  const transferObjects = data?.transferObjects ?? [];
  const securityEvents = data?.securityEvents ?? [];
  const threatIncidents = data?.threatIncidents ?? [];
  const trustEvents = data?.trustEvents ?? [];

  const selectedUser = userNodes.find((u) => u.id === selectedUserId) ?? null;
  const selectedUserTrustEvents = trustEvents.filter((te) => te.userId === selectedUserId);
  const selectedUserTransfers = transferObjects.filter(
    (t) => t.senderId === selectedUserId || t.recipientId === selectedUserId,
  );

  const selectedTransfer = transferObjects.find((t) => t.id === selectedTransferId) ?? null;

  return (
    <AppShell
      title="Security Digital Twin"
      description="Real-time SOC telemetry mirroring live users, cryptographic transfers, trust scores, locations, and threat response."
      actions={
        <div className="flex items-center gap-2.5">
          <label className="flex items-center gap-2 text-xs text-muted-foreground cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-primary"
            />
            <Radio
              className={cn(
                "size-3.5",
                autoRefresh ? "text-secure animate-pulse" : "text-muted-foreground",
              )}
            />
            Live Sync
          </label>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void refetch()}
            disabled={isFetching}
            className="h-8 gap-1.5"
          >
            <RefreshCw className={cn("size-3.5", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      }
    >
      {/* 1. TOP SUMMARY BANNER */}
      {isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-24 w-full" />
          ))}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <StatCard
            label="Active Users"
            value={summary?.activeUsers ?? 0}
            icon={Users}
            hint={`of ${summary?.totalUsers ?? 0} registered`}
          />
          <StatCard
            label="Active Transfers"
            value={summary?.activeTransfers ?? 0}
            icon={FileLock2}
            hint={`${summary?.totalTransfers ?? 0} total lifetime`}
          />
          <StatCard
            label="Trusted Users"
            value={summary?.trustedUsers ?? 0}
            icon={ShieldCheck}
            tone="secure"
            hint="Score 90–100"
          />
          <StatCard
            label="High-Risk Users"
            value={summary?.highRiskUsers ?? 0}
            icon={AlertTriangle}
            tone={summary?.highRiskUsers ? "critical" : "default"}
            hint="Score < 60 (Blocked)"
          />
          <StatCard
            label="Active Threats"
            value={summary?.activeThreats ?? 0}
            icon={ShieldAlert}
            tone={summary?.activeThreats ? "warning" : "default"}
            hint="Defensive response active"
          />
          <StatCard
            label="Blocked Transfers"
            value={summary?.blockedTransfers ?? 0}
            icon={Ban}
            tone="critical"
            hint="Policy enforced"
          />
        </div>
      )}

      {/* 2. GEOSPATIAL RADAR MAP */}
      <Card className="panel border-cyan-500/30 shadow-lg shadow-cyan-950/10">
        <CardHeader className="pb-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <CardTitle className="flex items-center gap-2 text-base font-semibold text-cyan-400">
                <Globe className="size-4" /> Live Geospatial Transfer Radar
              </CardTitle>
              <CardDescription className="text-xs">
                Observed transfer and session coordinates recorded with explicit user consent.
              </CardDescription>
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <span className="size-2 rounded-full bg-cyan-400 animate-ping" />
                {transferObjects.filter((t) => t.hasLocation).length} active location signals
              </span>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-3 pt-0">
          <DigitalTwinMap
            transfers={transferObjects}
            events={securityEvents}
            onSelectTransfer={(id) => setSelectedTransferId(id)}
            className="h-[440px]"
          />
        </CardContent>
      </Card>

      {/* 3. USER NODES & ECOSYSTEM TOPOLOGY */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* User Nodes Topology */}
        <Card className="panel lg:col-span-2">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                <Users className="size-4 text-primary" /> User Ecosystem Topology
              </CardTitle>
              <Badge variant="outline" className="mono text-[10px]">
                {userNodes.length} Nodes
              </Badge>
            </div>
            <CardDescription className="text-xs">
              Live trust posture of authenticated accounts in the secure transfer ecosystem.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {userNodes.length === 0 ? (
              <p className="text-sm text-muted-foreground py-6 text-center">
                No user nodes discovered.
              </p>
            ) : (
              <div className="grid gap-2.5 sm:grid-cols-2">
                {userNodes.map((u) => {
                  const status = u.trustStatus;
                  const isBlocked = u.trustScore < 60;
                  return (
                    <div
                      key={u.id}
                      onClick={() => setSelectedUserId(u.id)}
                      className={cn(
                        "group flex flex-col justify-between rounded-lg border p-3 cursor-pointer transition-all hover:border-primary/60",
                        status === "TRUSTED" && "border-secure/30 bg-secure/5 hover:bg-secure/10",
                        status === "NORMAL" && "border-primary/30 bg-primary/5 hover:bg-primary/10",
                        status === "CAUTION" &&
                          "border-warning/30 bg-warning/5 hover:bg-warning/10",
                        status === "HIGH RISK" &&
                          "border-critical/40 bg-critical/10 hover:bg-critical/15",
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="truncate text-sm font-semibold text-foreground group-hover:text-primary">
                            {u.fullName}
                          </p>
                          <p className="truncate text-xs text-muted-foreground">{u.email}</p>
                        </div>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[10px] shrink-0 font-bold",
                            status === "TRUSTED" && "border-secure text-secure",
                            status === "NORMAL" && "border-primary text-primary",
                            status === "CAUTION" && "border-warning text-warning",
                            status === "HIGH RISK" && "border-critical text-critical animate-pulse",
                          )}
                        >
                          {status}
                        </Badge>
                      </div>

                      <div className="mt-3 flex items-center justify-between border-t border-border/50 pt-2 text-[11px]">
                        <span className="mono">
                          Trust: <strong className="text-foreground">{u.trustScore}</strong>/100
                        </span>
                        <span className="text-muted-foreground">
                          {u.activeSessions} session{u.activeSessions === 1 ? "" : "s"} ·{" "}
                          {u.deviceCount} device{u.deviceCount === 1 ? "" : "s"}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </CardContent>
        </Card>

        {/* System Security Telemetry Summary */}
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-semibold">
              <Shield className="size-4 text-cyan-400" /> Continuous Verification Signals
            </CardTitle>
            <CardDescription className="text-xs">
              Platform-wide detection counters from the active threat engine.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border border-border/70 p-2.5 bg-surface/40">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  Token Replays
                </p>
                <p className="mono mt-1 text-base font-bold text-foreground">
                  {summary?.tokenReplays ?? 0}
                </p>
              </div>
              <div className="rounded-md border border-border/70 p-2.5 bg-surface/40">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  Integrity Violations
                </p>
                <p className="mono mt-1 text-base font-bold text-foreground">
                  {summary?.integrityFailures ?? 0}
                </p>
              </div>
              <div className="rounded-md border border-border/70 p-2.5 bg-surface/40">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  Unauthorized Access
                </p>
                <p className="mono mt-1 text-base font-bold text-foreground">
                  {summary?.unauthorizedAttempts ?? 0}
                </p>
              </div>
              <div className="rounded-md border border-border/70 p-2.5 bg-surface/40">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">
                  Active Threats
                </p>
                <p className="mono mt-1 text-base font-bold text-warning">
                  {summary?.activeThreats ?? 0}
                </p>
              </div>
            </div>

            <div className="rounded-md border border-border/70 p-3 bg-slate-900/60 text-xs space-y-1.5">
              <p className="font-semibold text-cyan-400 flex items-center gap-1.5">
                <Server className="size-3.5" /> Cryptographic Policy
              </p>
              <p className="text-muted-foreground text-[11px] leading-relaxed">
                AES-256-GCM authenticated encryption + RSA-OAEP-2048 key wrapping. All transfers
                requiring minimum receiver trust threshold (60).
              </p>
            </div>

            <Button variant="outline" size="sm" asChild className="w-full text-xs">
              <Link to="/security-lab">
                <ExternalLink className="mr-1.5 size-3.5" /> Launch Security Lab Simulation
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* 4. TRANSFER FLOW OBJECTS & SECURITY TIMELINE */}
      <div className="grid gap-4 lg:grid-cols-3">
        {/* Transfer Objects Stream */}
        <Card className="panel lg:col-span-2">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2 text-sm font-semibold">
                <FileLock2 className="size-4 text-primary" /> Secure Transfer Objects
              </CardTitle>
              <Badge variant="outline" className="mono text-[10px]">
                {transferObjects.length} In-Flight / Monitored
              </Badge>
            </div>
            <CardDescription className="text-xs">
              Digital Twin objects capturing full cryptographic pipelines, hashes, and statuses.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {transferObjects.length === 0 ? (
              <p className="text-sm text-muted-foreground py-8 text-center">
                No transfer objects created yet.
              </p>
            ) : (
              <ScrollArea className="max-h-[360px] pr-2">
                <div className="space-y-2.5">
                  {transferObjects.map((t) => {
                    const isTerminated = t.status === "TERMINATED";
                    const isCompleted = t.status === "COMPLETED";
                    return (
                      <div
                        key={t.id}
                        onClick={() => setSelectedTransferId(t.id)}
                        className={cn(
                          "rounded-lg border p-3 text-xs cursor-pointer transition-all hover:border-primary/70",
                          isTerminated
                            ? "border-critical/40 bg-critical/5"
                            : "border-border bg-surface/40 hover:bg-surface/70",
                        )}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="mono text-[10px]">
                              #TR-{t.id.slice(0, 8)}
                            </Badge>
                            <span className="font-semibold text-foreground">{t.fileName}</span>
                            <span className="text-muted-foreground">
                              ({formatBytes(t.fileSizeBytes)})
                            </span>
                          </div>
                          <Badge
                            variant="outline"
                            className={cn(
                              "text-[10px]",
                              isCompleted && "border-secure text-secure",
                              isTerminated && "border-critical text-critical font-bold",
                              !isCompleted && !isTerminated && "border-primary text-primary",
                            )}
                          >
                            {t.status}
                          </Badge>
                        </div>

                        <div className="mt-2.5 grid gap-1.5 sm:grid-cols-2 text-muted-foreground">
                          <p>
                            <strong>Sender:</strong> {t.senderName} (
                            <span className="mono">{t.senderTrustScore}</span>)
                          </p>
                          <p>
                            <strong>Recipient:</strong> {t.recipientName} (
                            <span className="mono">{t.recipientTrustScore}</span>)
                          </p>
                          <p>
                            <strong>Crypto:</strong> {t.encryptionAlgorithm} · {t.keyWrapAlgorithm}
                          </p>
                          <p className="truncate">
                            <strong>SHA-256:</strong>{" "}
                            <span className="mono">{t.originalSha256.slice(0, 16)}…</span>
                          </p>
                        </div>

                        {t.hasLocation ? (
                          <div className="mt-2 flex items-center gap-1.5 text-[10px] text-cyan-400">
                            <MapPin className="size-3" /> Location signal captured and linked to
                            Digital Twin
                          </div>
                        ) : null}
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>

        {/* Security Event & Threat Feed */}
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-semibold">
              <Activity className="size-4 text-warning" /> Security Event Stream
            </CardTitle>
            <CardDescription className="text-xs">
              Live audit and threat detections updating the Digital Twin state.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {securityEvents.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">
                No security events recorded yet.
              </p>
            ) : (
              <ScrollArea className="max-h-[360px] pr-2">
                <div className="space-y-2">
                  {securityEvents.slice(0, 20).map((e) => {
                    const isCritical = e.severity === "critical" || e.severity === "high";
                    return (
                      <div
                        key={e.id}
                        className={cn(
                          "rounded-md border p-2 text-xs",
                          isCritical
                            ? "border-critical/40 bg-critical/5"
                            : "border-border bg-surface/30",
                        )}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="mono font-semibold text-foreground">{e.eventType}</span>
                          <ThreatLevelBadge level={e.severity} />
                        </div>
                        <p className="text-[11px] text-muted-foreground mt-0.5">{e.userEmail}</p>
                        <div className="mt-1 flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>{new Date(e.createdAt).toLocaleTimeString()}</span>
                          {e.trustDelta !== 0 ? (
                            <span className="mono text-critical font-semibold">
                              trust {e.trustDelta}
                            </span>
                          ) : null}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </ScrollArea>
            )}
          </CardContent>
        </Card>
      </div>

      {/* 5. USER SECURITY PROFILE DIALOG */}
      <Dialog
        open={Boolean(selectedUserId)}
        onOpenChange={(o) => (!o ? setSelectedUserId(null) : undefined)}
      >
        <DialogContent className="max-w-2xl bg-slate-950 border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-lg">
              <User className="size-5 text-primary" /> User Security Profile
            </DialogTitle>
            <DialogDescription>
              Detailed trust history, active devices, sessions, and transfers for this node.
            </DialogDescription>
          </DialogHeader>

          {selectedUser ? (
            <div className="space-y-4">
              <div className="grid gap-2 sm:grid-cols-3">
                <div className="rounded-md border border-border/80 p-3 bg-surface/40">
                  <p className="text-[10px] uppercase text-muted-foreground">User Name</p>
                  <p className="font-semibold mt-1">{selectedUser.fullName}</p>
                  <p className="text-xs text-muted-foreground">{selectedUser.email}</p>
                </div>
                <div className="rounded-md border border-border/80 p-3 bg-surface/40">
                  <p className="text-[10px] uppercase text-muted-foreground">Trust Score</p>
                  <p className="mono text-xl font-bold mt-1 text-foreground">
                    {selectedUser.trustScore} / 100
                  </p>
                  <p className="text-xs text-muted-foreground">{selectedUser.trustStatus}</p>
                </div>
                <div className="rounded-md border border-border/80 p-3 bg-surface/40">
                  <p className="text-[10px] uppercase text-muted-foreground">Account Status</p>
                  <p className="font-semibold mt-1 uppercase text-secure">
                    {selectedUser.accountStatus}
                  </p>
                  <p className="text-xs text-muted-foreground">
                    {selectedUser.activeSessions} active sessions
                  </p>
                </div>
              </div>

              {/* Trust History Breakdown */}
              <div className="rounded-md border border-border/80 p-3 bg-surface/30 space-y-2">
                <p className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                  <ShieldCheck className="size-4 text-primary" /> Trust Score History &amp; Mutation
                  Reasons
                </p>
                {selectedUserTrustEvents.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No deductions recorded. Default starting trust: 100/100.
                  </p>
                ) : (
                  <ScrollArea className="max-h-40">
                    <div className="space-y-1.5">
                      {selectedUserTrustEvents.map((te) => (
                        <div
                          key={te.id}
                          className="flex items-center justify-between text-xs border-b border-border/40 pb-1 last:border-0"
                        >
                          <div>
                            <p className="font-medium text-foreground">{te.reason}</p>
                            <p className="text-[10px] text-muted-foreground">
                              {new Date(te.createdAt).toLocaleString()}
                            </p>
                          </div>
                          <div className="text-right">
                            <span className="mono text-critical font-bold">{te.delta}</span>
                            <p className="mono text-[10px] text-muted-foreground">
                              {te.previousScore} → {te.newScore}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                )}
              </div>

              {/* User Transfers */}
              <div className="rounded-md border border-border/80 p-3 bg-surface/30 space-y-2">
                <p className="text-xs font-semibold text-foreground">Recent Transfers Involved</p>
                {selectedUserTransfers.length === 0 ? (
                  <p className="text-xs text-muted-foreground">
                    No transfers recorded for this user.
                  </p>
                ) : (
                  <div className="space-y-1.5 max-h-36 overflow-y-auto">
                    {selectedUserTransfers.slice(0, 5).map((t) => (
                      <div
                        key={t.id}
                        className="flex items-center justify-between text-xs border-b border-border/30 pb-1 last:border-0"
                      >
                        <span className="mono">{t.fileName}</span>
                        <Badge variant="outline" className="text-[10px]">
                          {t.status}
                        </Badge>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>

      {/* 6. TRANSFER SECURITY PROFILE DIALOG */}
      <Dialog
        open={Boolean(selectedTransferId)}
        onOpenChange={(o) => (!o ? setSelectedTransferId(null) : undefined)}
      >
        <DialogContent className="max-w-2xl bg-slate-950 border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-lg">
              <FileLock2 className="size-5 text-cyan-400" /> Transfer Security Profile
            </DialogTitle>
            <DialogDescription>
              End-to-end cryptographic and forensic verification records for this transfer.
            </DialogDescription>
          </DialogHeader>

          {selectedTransfer ? (
            <div className="space-y-4 text-xs">
              <div className="grid gap-2 sm:grid-cols-2">
                <div className="rounded-md border border-border p-2.5 bg-surface/40">
                  <p className="text-[10px] uppercase text-muted-foreground">Transfer Ref</p>
                  <p className="mono font-bold mt-0.5">#TR-{selectedTransfer.id.slice(0, 8)}</p>
                  <p className="text-muted-foreground mt-1">
                    File: {selectedTransfer.fileName} ({formatBytes(selectedTransfer.fileSizeBytes)}
                    )
                  </p>
                </div>
                <div className="rounded-md border border-border p-2.5 bg-surface/40">
                  <p className="text-[10px] uppercase text-muted-foreground">Security Status</p>
                  <p className="font-bold mt-0.5 text-cyan-400">{selectedTransfer.status}</p>
                  <p className="text-muted-foreground mt-1">
                    Created: {new Date(selectedTransfer.createdAt).toLocaleString()}
                  </p>
                </div>
              </div>

              <div className="rounded-md border border-border p-3 bg-surface/30 space-y-2">
                <p className="font-semibold text-foreground">Cryptographic Specifications</p>
                <div className="grid gap-2 sm:grid-cols-3">
                  <div>
                    <span className="text-muted-foreground">Confidentiality:</span>
                    <p className="mono font-medium text-foreground">
                      {selectedTransfer.encryptionAlgorithm}
                    </p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Key Protection:</span>
                    <p className="mono font-medium text-foreground">
                      {selectedTransfer.keyWrapAlgorithm}
                    </p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Integrity:</span>
                    <p className="mono font-medium text-foreground">
                      {selectedTransfer.hashAlgorithm} Match
                    </p>
                  </div>
                </div>
              </div>

              <div className="rounded-md border border-border p-3 bg-surface/30 space-y-1.5">
                <p className="font-semibold text-foreground">Parties &amp; Trust Posture</p>
                <div className="flex justify-between">
                  <span>
                    Sender: <strong>{selectedTransfer.senderName}</strong>
                  </span>
                  <span className="mono">Trust Score: {selectedTransfer.senderTrustScore}/100</span>
                </div>
                <div className="flex justify-between">
                  <span>
                    Recipient: <strong>{selectedTransfer.recipientName}</strong>
                  </span>
                  <span className="mono">
                    Trust Score: {selectedTransfer.recipientTrustScore}/100
                  </span>
                </div>
              </div>

              {selectedTransfer.hasLocation ? (
                <div className="rounded-md border border-cyan-500/30 bg-cyan-950/20 p-3 text-cyan-300 space-y-1">
                  <p className="font-semibold flex items-center gap-1.5">
                    <MapPin className="size-3.5" /> Consented Geospatial Coordinates
                  </p>
                  {selectedTransfer.senderLatitude ? (
                    <p className="mono">
                      Sender: {selectedTransfer.senderLatitude.toFixed(4)},{" "}
                      {selectedTransfer.senderLongitude?.toFixed(4)}
                    </p>
                  ) : null}
                  {selectedTransfer.receiverLatitude ? (
                    <p className="mono">
                      Receiver: {selectedTransfer.receiverLatitude.toFixed(4)},{" "}
                      {selectedTransfer.receiverLongitude?.toFixed(4)}
                    </p>
                  ) : null}
                </div>
              ) : null}

              <div className="flex justify-end gap-2 pt-2">
                <Button variant="outline" size="sm" asChild>
                  <Link to="/transfer/$id" params={{ id: selectedTransfer.id }}>
                    <ExternalLink className="mr-1.5 size-3.5" /> Full Transfer Audit
                  </Link>
                </Button>
              </div>
            </div>
          ) : null}
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
