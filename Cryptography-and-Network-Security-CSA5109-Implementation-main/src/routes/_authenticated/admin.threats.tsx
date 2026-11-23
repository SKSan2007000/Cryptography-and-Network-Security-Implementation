import { createFileRoute } from "@tanstack/react-router";
import { format } from "date-fns";

import { AppShell } from "@/components/layout/AppShell";
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
import { ThreatLevelBadge } from "@/components/security/ThreatLevelBadge";
import { useIncidents } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/admin/threats")({
  head: () => ({
    meta: [
      { title: "Threat Incidents — SentinelCrypt Admin" },
      {
        name: "description",
        content: "Every detected threat, its response action and trust impact.",
      },
    ],
  }),
  component: AdminThreatsPage,
});

function AdminThreatsPage() {
  const overview = useIncidents(300);
  const rows = overview.data ?? [];

  return (
    <AppShell
      title="Threat Incidents"
      description="All detected threats across the platform, including demo simulations."
    >
      <Card className="panel">
        <CardContent className="p-0">
          {overview.isLoading ? (
            <div className="space-y-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : rows.length === 0 ? (
            <p className="p-8 text-center text-sm text-muted-foreground">
              No threat incidents recorded.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-32">Time</TableHead>
                  <TableHead>Threat</TableHead>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead className="w-36">Response</TableHead>
                  <TableHead className="w-20">Trust</TableHead>
                  <TableHead className="w-24">Blocked</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="mono text-xs text-muted-foreground">
                      {format(new Date(i.created_at), "dd MMM HH:mm:ss")}
                    </TableCell>
                    <TableCell className="text-xs font-medium">
                      {i.threat_type.replace(/_/g, " ")}
                      {i.simulated ? (
                        <span className="ml-1.5 text-[10px] text-warning">DEMO SIMULATION</span>
                      ) : null}
                    </TableCell>
                    <TableCell>
                      <ThreatLevelBadge level={i.severity} />
                    </TableCell>
                    <TableCell className="mono text-[11px] text-muted-foreground">
                      {i.action_taken.replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="mono text-xs text-critical">{i.trust_delta}</TableCell>
                    <TableCell className="text-xs">{i.blocked ? "yes" : "no"}</TableCell>
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
