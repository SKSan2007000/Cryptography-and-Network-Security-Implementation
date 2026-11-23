import { createFileRoute, Link } from "@tanstack/react-router";
import { format } from "date-fns";
import { Globe, History, Loader2, ShieldAlert, Users } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { supabase } from "@/integrations/supabase/client";
import { getTrustStatus } from "@/lib/security-rules";
import { adminAction } from "@/lib/sentinel.functions";
import { cn } from "@/lib/utils";
import { useAdminOverview } from "./admin.index";

export const Route = createFileRoute("/_authenticated/admin/users")({
  head: () => ({
    meta: [
      { title: "Users — SentinelCrypt Admin" },
      { name: "description", content: "Manage user trust scores, suspension and sessions." },
    ],
  }),
  component: AdminUsersPage,
});

type UserAction = "SUSPEND_USER" | "REINSTATE_USER" | "RESET_TRUST" | "REVOKE_SESSIONS";

interface TrustEventRecord {
  id: string;
  user_id: string;
  previous_score: number;
  new_score: number;
  score_delta: number;
  event_type: string;
  event_category: string;
  reason: string;
  created_at: string;
}

function AdminUsersPage() {
  const overview = useAdminOverview();
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedUserForHistory, setSelectedUserForHistory] = useState<{
    id: string;
    name: string;
    email: string;
    score: number;
  } | null>(null);
  const [trustEvents, setTrustEvents] = useState<TrustEventRecord[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [filterBand, setFilterBand] = useState<string>("ALL");

  async function act(action: UserAction, targetUserId: string) {
    setBusy(`${action}:${targetUserId}`);
    try {
      await adminAction({ data: { action, targetUserId, transferId: null } });
      toast.success(`${action.replace(/_/g, " ").toLowerCase()} applied.`);
      await overview.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Action failed.");
    } finally {
      setBusy(null);
    }
  }

  async function openTrustHistory(u: {
    id: string;
    full_name: string | null;
    email: string;
    trust_score: number;
  }) {
    setSelectedUserForHistory({
      id: u.id,
      name: u.full_name ?? u.email,
      email: u.email,
      score: u.trust_score,
    });
    setLoadingHistory(true);
    try {
      const { data, error } = await supabase
        .from("trust_events")
        .select("*")
        .eq("user_id", u.id)
        .order("created_at", { ascending: false });

      if (error) {
        console.error("Failed to load trust events:", error);
        setTrustEvents([]);
      } else {
        const events: TrustEventRecord[] = ((data as Array<Record<string, unknown>>) ?? []).map(
          (row) => ({
            id: String(row["id"] ?? ""),
            user_id: String(row["user_id"] ?? ""),
            previous_score: Number(row["previous_score"] ?? 100),
            new_score: Number(row["new_score"] ?? 100),
            score_delta: Number(row["delta"] ?? 0),
            event_type: row["reason"]
              ? String(row["reason"]).split(" ")[0]!.toUpperCase()
              : "TRUST_CHANGE",
            event_category: "TRUST",
            reason: String(row["reason"] ?? ""),
            created_at: String(row["created_at"] ?? new Date().toISOString()),
          }),
        );
        setTrustEvents(events);
      }
    } catch (err) {
      console.error(err);
      setTrustEvents([]);
    } finally {
      setLoadingHistory(false);
    }
  }

  const allUsers = overview.data?.users ?? [];
  const filteredUsers = allUsers.filter((u) => {
    if (filterBand === "ALL") return true;
    const status = getTrustStatus(u.trust_score);
    return status === filterBand;
  });

  return (
    <AppShell
      title="User Management"
      description="Trust scores, continuous risk assessment, and session security."
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
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant={filterBand === "ALL" ? "secondary" : "ghost"}
            onClick={() => setFilterBand("ALL")}
            className="text-xs"
          >
            All Users ({allUsers.length})
          </Button>
          <Button
            size="sm"
            variant={filterBand === "HIGH RISK" ? "secondary" : "ghost"}
            onClick={() => setFilterBand("HIGH RISK")}
            className="text-xs text-destructive"
          >
            High Risk (
            {allUsers.filter((u) => getTrustStatus(u.trust_score) === "HIGH RISK").length})
          </Button>
          <Button
            size="sm"
            variant={filterBand === "CAUTION" ? "secondary" : "ghost"}
            onClick={() => setFilterBand("CAUTION")}
            className="text-xs text-amber-400"
          >
            Caution ({allUsers.filter((u) => getTrustStatus(u.trust_score) === "CAUTION").length})
          </Button>
          <Button
            size="sm"
            variant={filterBand === "NORMAL" ? "secondary" : "ghost"}
            onClick={() => setFilterBand("NORMAL")}
            className="text-xs text-sky-400"
          >
            Normal ({allUsers.filter((u) => getTrustStatus(u.trust_score) === "NORMAL").length})
          </Button>
          <Button
            size="sm"
            variant={filterBand === "TRUSTED" ? "secondary" : "ghost"}
            onClick={() => setFilterBand("TRUSTED")}
            className="text-xs text-emerald-400"
          >
            Trusted ({allUsers.filter((u) => getTrustStatus(u.trust_score) === "TRUSTED").length})
          </Button>
        </div>
      </div>

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
                  <TableHead>User</TableHead>
                  <TableHead className="w-36">Trust Score</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-28">Joined</TableHead>
                  <TableHead className="w-80">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredUsers.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={5}
                      className="py-8 text-center text-sm text-muted-foreground"
                    >
                      No users match the selected filter.
                    </TableCell>
                  </TableRow>
                ) : (
                  filteredUsers.map((u) => {
                    const status = getTrustStatus(u.trust_score);
                    const isBlocked = u.trust_score < 60;
                    return (
                      <TableRow key={u.id}>
                        <TableCell>
                          <p className="text-sm font-medium">{u.full_name ?? "—"}</p>
                          <p className="text-xs text-muted-foreground">{u.email}</p>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className="mono text-sm font-bold">{u.trust_score}</span>
                            <Badge
                              variant="outline"
                              className={cn(
                                "text-[10px] uppercase font-semibold",
                                status === "TRUSTED" &&
                                  "border-emerald-500/40 bg-emerald-500/10 text-emerald-400",
                                status === "NORMAL" &&
                                  "border-sky-500/40 bg-sky-500/10 text-sky-400",
                                status === "CAUTION" &&
                                  "border-amber-500/40 bg-amber-500/10 text-amber-400",
                                status === "HIGH RISK" &&
                                  "border-destructive/40 bg-destructive/10 text-destructive animate-pulse",
                              )}
                            >
                              {status}
                            </Badge>
                          </div>
                          {isBlocked ? (
                            <p className="mt-0.5 text-[10px] font-semibold text-destructive">
                              Transfers Blocked (&lt;60)
                            </p>
                          ) : null}
                        </TableCell>
                        <TableCell>
                          <ThreatLevelBadge
                            level={u.status === "active" ? "secure" : "critical"}
                            label={u.status.toUpperCase()}
                          />
                        </TableCell>
                        <TableCell className="mono text-xs text-muted-foreground">
                          {format(new Date(u.created_at), "dd MMM yy")}
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            <Button
                              size="sm"
                              variant="outline"
                              className="gap-1 text-xs"
                              onClick={() => void openTrustHistory(u)}
                            >
                              <History className="size-3 text-muted-foreground" />
                              Audit
                            </Button>
                            {u.status === "active" ? (
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busy !== null}
                                onClick={() => void act("SUSPEND_USER", u.id)}
                              >
                                {busy === `SUSPEND_USER:${u.id}` ? (
                                  <Loader2 className="size-3 animate-spin" />
                                ) : (
                                  "Suspend"
                                )}
                              </Button>
                            ) : (
                              <Button
                                size="sm"
                                variant="outline"
                                disabled={busy !== null}
                                onClick={() => void act("REINSTATE_USER", u.id)}
                              >
                                Reinstate
                              </Button>
                            )}
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy !== null || u.trust_score === 100}
                              onClick={() => void act("RESET_TRUST", u.id)}
                            >
                              Reset trust
                            </Button>
                            <Button
                              size="sm"
                              variant="outline"
                              disabled={busy !== null}
                              onClick={() => void act("REVOKE_SESSIONS", u.id)}
                            >
                              Revoke
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Trust History Dialog */}
      <Dialog
        open={selectedUserForHistory !== null}
        onOpenChange={(open) => {
          if (!open) setSelectedUserForHistory(null);
        }}
      >
        <DialogContent className="max-w-2xl bg-card border-border">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-base">
              <History className="size-4 text-primary" />
              Trust Mutation History
            </DialogTitle>
            <DialogDescription className="text-xs text-muted-foreground">
              {selectedUserForHistory?.name} ({selectedUserForHistory?.email}) — Current Trust
              Score:{" "}
              <strong className="mono text-foreground">{selectedUserForHistory?.score}/100</strong>
            </DialogDescription>
          </DialogHeader>

          <ScrollArea className="max-h-96 pr-2">
            {loadingHistory ? (
              <div className="space-y-2 py-4">
                {Array.from({ length: 3 }).map((_, i) => (
                  <Skeleton key={i} className="h-12 w-full" />
                ))}
              </div>
            ) : trustEvents.length === 0 ? (
              <div className="py-8 text-center text-sm text-muted-foreground">
                <p>No trust deduction or recovery events recorded for this user.</p>
                <p className="text-xs text-muted-foreground/70 mt-1">
                  Baseline trust score is pristine (100).
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                {trustEvents.map((evt) => {
                  const isNegative = evt.score_delta < 0;
                  return (
                    <div
                      key={evt.id}
                      className="flex items-start justify-between gap-3 rounded-lg border border-border/80 bg-surface/50 p-3 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="mono font-semibold text-foreground">
                            {evt.event_type.replace(/_/g, " ")}
                          </span>
                          <Badge variant="outline" className="text-[10px] text-muted-foreground">
                            {evt.event_category}
                          </Badge>
                        </div>
                        <p className="text-muted-foreground">{evt.reason}</p>
                        <p className="mono text-[10px] text-muted-foreground/70">
                          {format(new Date(evt.created_at), "dd MMM yyyy · HH:mm:ss")}
                        </p>
                      </div>

                      <div className="text-right shrink-0">
                        <span
                          className={cn(
                            "mono text-sm font-bold",
                            isNegative ? "text-destructive" : "text-emerald-400",
                          )}
                        >
                          {evt.score_delta > 0 ? `+${evt.score_delta}` : evt.score_delta}
                        </span>
                        <p className="mono text-[10px] text-muted-foreground">
                          {evt.previous_score} &rarr; {evt.new_score}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
