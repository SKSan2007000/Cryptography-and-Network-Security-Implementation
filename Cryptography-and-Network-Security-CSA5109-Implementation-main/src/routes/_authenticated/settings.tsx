import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { format } from "date-fns";
import { Loader2, LogOut, MonitorSmartphone, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SessionStatus } from "@/components/security/SessionStatus";
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { useQueryClient } from "@tanstack/react-query";
import { useSessions } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Settings — SentinelCrypt" },
      { name: "description", content: "Session management and security preferences." },
    ],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const sessions = useSessions(user?.id);
  const [busyId, setBusyId] = useState<string | null>(null);

  async function revokeSession(id: string) {
    setBusyId(id);
    const { error } = await supabase
      .from("app_sessions")
      .update({ revoked: true, revoked_reason: "USER_REVOKED" })
      .eq("id", id);
    setBusyId(null);
    if (error) {
      toast.error(error.message);
    } else {
      toast.success("Session revoked.");
      void sessions.refetch();
    }
  }

  async function handleSignOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await signOut();
    void navigate({ to: "/auth", replace: true });
  }

  return (
    <AppShell title="Settings" description="Security preferences and session management.">
      <Card className="panel">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldCheck className="size-4 text-secure" /> Current Session
          </CardTitle>
          <CardDescription>
            Sessions expire after 12 hours and are monitored for IP and device anomalies.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SessionStatus />
        </CardContent>
      </Card>

      <Card className="panel">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm">
            <MonitorSmartphone className="size-4" /> Session Management
          </CardTitle>
          <CardDescription>Revoke any session you do not recognise.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          {(sessions.data ?? []).map((s) => (
            <div
              key={s.id}
              className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3"
            >
              <div className="min-w-0">
                <p className="mono text-xs">{s.ip_address ?? "unknown ip"}</p>
                <p className="mono text-[10px] text-muted-foreground">
                  started {format(new Date(s.created_at), "dd MMM HH:mm")} · expires{" "}
                  {format(new Date(s.expires_at), "dd MMM HH:mm")}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <ThreatLevelBadge
                  level={s.revoked ? "critical" : "secure"}
                  label={s.revoked ? "REVOKED" : "ACTIVE"}
                />
                {!s.revoked ? (
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={busyId === s.id}
                    onClick={() => void revokeSession(s.id)}
                  >
                    {busyId === s.id ? <Loader2 className="size-3.5 animate-spin" /> : "Revoke"}
                  </Button>
                ) : null}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="panel border-critical/30">
        <CardHeader>
          <CardTitle className="text-sm text-critical">Sign Out</CardTitle>
          <CardDescription>
            Ends the monitored session and clears cached data on this device.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Button variant="destructive" onClick={() => void handleSignOut()}>
            <LogOut className="mr-2 size-4" /> Sign out of SentinelCrypt
          </Button>
        </CardContent>
      </Card>
    </AppShell>
  );
}
