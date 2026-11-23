import { createFileRoute } from "@tanstack/react-router";
import { format } from "date-fns";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { TransferStateBadge } from "@/components/security/TransferStateBadge";
import { adminAction } from "@/lib/sentinel.functions";
import { useAdminOverview } from "./admin.index";

export const Route = createFileRoute("/_authenticated/admin/transfers")({
  head: () => ({
    meta: [
      { title: "Transfers — SentinelCrypt Admin" },
      { name: "description", content: "Monitor and terminate transfers platform-wide." },
    ],
  }),
  component: AdminTransfersPage,
});

const TERMINABLE = new Set(["CREATED", "ENCRYPTING", "ENCRYPTED", "TRANSFERRING", "VERIFYING"]);

function AdminTransfersPage() {
  const overview = useAdminOverview();
  const [busy, setBusy] = useState<string | null>(null);

  async function terminate(transferId: string, senderId: string) {
    setBusy(transferId);
    try {
      await adminAction({
        data: { action: "TERMINATE_TRANSFER", targetUserId: senderId, transferId },
      });
      toast.success("Transfer terminated.");
      await overview.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Action failed.");
    } finally {
      setBusy(null);
    }
  }

  const rows = overview.data?.transfers ?? [];

  return (
    <AppShell title="All Transfers" description="Platform-wide transfer monitoring and control.">
      <Card className="panel">
        <CardContent className="p-0">
          {overview.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Transfer</TableHead>
                  <TableHead className="w-32">Status</TableHead>
                  <TableHead className="w-32">Created</TableHead>
                  <TableHead className="w-28">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="mono text-xs">{t.id.slice(0, 8)}…</TableCell>
                    <TableCell>
                      <TransferStateBadge state={t.status} />
                    </TableCell>
                    <TableCell className="mono text-xs text-muted-foreground">
                      {format(new Date(t.created_at), "dd MMM HH:mm")}
                    </TableCell>
                    <TableCell>
                      {TERMINABLE.has(t.status) ? (
                        <Button
                          size="sm"
                          variant="destructive"
                          disabled={busy === t.id}
                          onClick={() => void terminate(t.id, t.sender_id)}
                        >
                          Terminate
                        </Button>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </AppShell>
  );
}
