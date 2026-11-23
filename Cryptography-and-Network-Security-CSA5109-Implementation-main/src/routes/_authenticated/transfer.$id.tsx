import { useQueryClient } from "@tanstack/react-query";
import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { DownloadControl } from "@/components/security/DownloadControl";
import { IntegrityStatus } from "@/components/security/IntegrityStatus";
import { SecureDownloadDialog } from "@/components/security/SecureDownloadDialog";
import { SecurityDemo } from "@/components/security/SecurityDemo";
import { SecurityDetailsPanel } from "@/components/security/SecurityDetailsPanel";
import { SenderTokenPanel } from "@/components/security/SenderTokenPanel";
import { SecurityTimeline } from "@/components/security/SecurityTimeline";
import { EmptyState } from "@/components/security/StatCard";
import { ThreatAlert } from "@/components/security/ThreatAlert";
import { useAuth } from "@/hooks/useAuth";
import {
  firstFile,
  useAuditLogs,
  useProfileMap,
  useSecurityEvents,
  useTransfer,
  useTransferKeys,
  useTransferMetadata,
  useTransferNotifications,
} from "@/lib/queries";
import { getKeyRecord } from "@/lib/keyvault";
import { receiveSecureTransfer, type ReceiveOutcome } from "@/lib/transfer-client";
import { downloadBlockReason, isDownloadable } from "@/lib/transfer-state";
import { TransferLifecycle } from "@/components/security/TransferLifecycle";

export const Route = createFileRoute("/_authenticated/transfer/$id")({
  head: () => ({
    meta: [
      { title: "Transfer Details — SentinelCrypt" },
      {
        name: "description",
        content:
          "Full security analysis, integrity status and audit trail for a SentinelCrypt transfer.",
      },
    ],
  }),
  component: TransferDetailsPage,
});

function TransferDetailsPage() {
  const { id } = Route.useParams();
  const { user, refreshProfile } = useAuth();
  const queryClient = useQueryClient();
  const transfer = useTransfer(id);
  const metadata = useTransferMetadata(id);
  const keys = useTransferKeys(id);
  const events = useSecurityEvents(100);
  const audit = useAuditLogs({ transferId: id, limit: 50 });
  const notifications = useTransferNotifications(id);
  const profiles = useProfileMap();

  const [busy, setBusy] = useState(false);
  const [steps, setSteps] = useState<string[]>([]);
  const [outcome, setOutcome] = useState<ReceiveOutcome | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [unlockOpen, setUnlockOpen] = useState(false);
  const [hasKeys, setHasKeys] = useState(false);

  useEffect(() => {
    if (!user) return;
    void getKeyRecord(user.id).then((r) => setHasKeys(Boolean(r)));
  }, [user]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = window.setInterval(() => void queryClient.invalidateQueries(), 8000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, queryClient]);

  if (transfer.isLoading) {
    return (
      <AppShell title="Transfer Details">
        <div className="space-y-3">
          <Skeleton className="h-40 w-full" />
          <Skeleton className="h-64 w-full" />
        </div>
      </AppShell>
    );
  }

  const t = transfer.data;
  if (!t) {
    return (
      <AppShell title="Transfer Not Found">
        <EmptyState
          icon={ShieldAlert}
          title="Transfer unavailable"
          description="This transfer does not exist or you are not a party to it."
          action={
            <Button asChild variant="outline" size="sm">
              <Link to="/dashboard">Back to dashboard</Link>
            </Button>
          }
        />
      </AppShell>
    );
  }

  const isSender = t.sender_id === user?.id;
  const file = firstFile(t) ?? metadata.data ?? null;
  const counterpartyId = isSender ? t.recipient_id : t.sender_id;
  const counterpartyLabel =
    profiles.map.get(counterpartyId)?.full_name ??
    profiles.map.get(counterpartyId)?.email ??
    "Unknown user";
  const remaining = Math.max(t.max_downloads - t.download_count, 0);
  const transferEvents = (events.data ?? []).filter((e) => e.transfer_id === id);
  const integrityState =
    t.status === "COMPLETED"
      ? "verified"
      : t.status === "TERMINATED" && (t.terminated_reason ?? "").includes("INTEGRITY")
        ? "failed"
        : "pending";

  async function handleDownload(token: string, passphrase: string) {
    if (!user || !t || !file) return;
    setBusy(true);
    setSteps([]);
    setOutcome(null);
    try {
      const result = await receiveSecureTransfer({
        transferId: t.id,
        token,
        userId: user.id,
        passphrase,
        fileName: file.original_name,
        onStep: (message) => setSteps((prev) => [...prev, message]),
      });
      setOutcome(result);
      if (result.ok) {
        toast.success("Integrity verified — file downloaded securely.");
      } else {
        toast.error(result.reason);
      }
      setUnlockOpen(false);
      void refreshProfile();
      void queryClient.invalidateQueries();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Download failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell
      title="Transfer Details"
      description={
        file ? `${file.original_name} — full security analysis` : "Full security analysis"
      }
      actions={
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="accent-current"
            />
            Auto-refresh
          </label>
          <Button variant="outline" asChild>
            <Link to={isSender ? "/sent" : "/inbox"}>
              <ArrowLeft className="mr-1.5 size-4" /> Back
            </Link>
          </Button>
        </div>
      }
    >
      <SecurityDetailsPanel
        transfer={t}
        metadata={file}
        keyAlgorithm={keys.data?.[0]?.wrap_algorithm ?? null}
        events={transferEvents}
        counterpartyLabel={counterpartyLabel}
        isSender={isSender}
      />

      {isSender && user ? (
        <SenderTokenPanel userId={user.id} sealedToken={t.sender_token_wrapped} />
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <IntegrityStatus
          state={integrityState}
          expected={t.original_sha256}
          computed={integrityState === "verified" ? t.original_sha256 : null}
        />
        <div className="panel p-4">
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Secure Download
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            Access token + your key passphrase are required. Your key passphrase protects your RSA
            private key and is different from the one-time transfer access token. SHA-256 is
            verified before release.
          </p>
          <div className="mt-3">
            <DownloadControl
              fileName={file?.original_name ?? "payload.bin"}
              disabled={isSender || !isDownloadable(t.status)}
              disabledReason={
                isSender ? "Only the receiver can download" : downloadBlockReason(t.status)
              }
              remaining={remaining}
              busy={busy}
              onDownload={() => setUnlockOpen(true)}
            />
          </div>
          <SecureDownloadDialog
            open={unlockOpen}
            onOpenChange={setUnlockOpen}
            hasKeys={hasKeys}
            busy={busy}
            onSubmit={(token, passphrase) => void handleDownload(token, passphrase)}
          />
          {steps.length > 0 ? (
            <ol className="mt-3 space-y-1">
              {steps.map((s, i) => (
                <li key={i} className="mono text-[11px] text-muted-foreground">
                  ✓ {s}
                </li>
              ))}
            </ol>
          ) : null}
          {outcome && !outcome.ok ? (
            <div className="mt-3">
              <ThreatAlert
                threat={{
                  label: outcome.label ?? "Download blocked",
                  severity: outcome.severity ?? "high",
                  action: outcome.action ?? "TERMINATE_TRANSFER",
                  trustDelta: outcome.trustDelta ?? 0,
                  description: outcome.reason,
                }}
              />
            </div>
          ) : null}
        </div>
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Security Timeline
            </CardTitle>
          </CardHeader>
          <CardContent>
            <TransferLifecycle events={audit.data ?? []} status={t.status} />
            <div className="mt-4 border-t border-border pt-3">
              <SecurityTimeline
                events={audit.data ?? []}
                emptyLabel="No audit entries for this transfer yet."
              />
            </div>
          </CardContent>
        </Card>
      </div>

      {(notifications.data ?? []).length > 0 ? (
        <Card className="panel">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">
              Security Notifications
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {(notifications.data ?? []).map((n) => (
              <div key={n.id} className="rounded-md border border-border p-3">
                <p className="text-sm font-medium">{n.title}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">{n.body}</p>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {(t.metrics as Record<string, unknown> | null)?.["simulated"] ? (
        <SecurityDemo
          transferId={t.id}
          onComplete={() => {
            void queryClient.invalidateQueries();
            void refreshProfile();
          }}
        />
      ) : null}
    </AppShell>
  );
}
