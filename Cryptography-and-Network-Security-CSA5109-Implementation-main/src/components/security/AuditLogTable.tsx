import { format } from "date-fns";

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Skeleton } from "@/components/ui/skeleton";
import { ThreatLevelBadge } from "./ThreatLevelBadge";

export type AuditRow = {
  id: string;
  created_at: string;
  event: string;
  severity: string;
  ip_address: string | null;
  action: string | null;
  transfer_id: string | null;
  metadata: unknown;
};

export function AuditLogTable({
  rows,
  loading,
  showTransfer = true,
}: {
  rows: AuditRow[];
  loading?: boolean;
  showTransfer?: boolean;
}) {
  if (loading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border p-8 text-center">
        <p className="text-sm font-medium">No audit entries yet</p>
        <p className="text-xs text-muted-foreground">
          Every login, encryption step, download and threat response will appear here.
        </p>
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-44">Timestamp</TableHead>
            <TableHead>Event</TableHead>
            <TableHead className="w-28">Severity</TableHead>
            <TableHead className="w-32">IP</TableHead>
            <TableHead className="w-40">Action</TableHead>
            {showTransfer ? <TableHead className="w-32">Transfer</TableHead> : null}
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.id}>
              <TableCell className="mono text-xs text-muted-foreground">
                {format(new Date(row.created_at), "dd MMM HH:mm:ss")}
              </TableCell>
              <TableCell className="mono text-xs">{row.event}</TableCell>
              <TableCell>
                <ThreatLevelBadge level={row.severity} />
              </TableCell>
              <TableCell className="mono text-xs text-muted-foreground">
                {row.ip_address ?? "—"}
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">{row.action ?? "—"}</TableCell>
              {showTransfer ? (
                <TableCell className="mono text-xs text-muted-foreground">
                  {row.transfer_id ? row.transfer_id.slice(0, 8) : "—"}
                </TableCell>
              ) : null}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}
