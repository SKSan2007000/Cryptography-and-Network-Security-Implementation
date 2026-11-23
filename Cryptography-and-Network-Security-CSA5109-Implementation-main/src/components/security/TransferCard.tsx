import { formatDistanceToNow } from "date-fns";
import { ArrowDownToLine, ArrowUpFromLine, FileLock2 } from "lucide-react";

import { Card, CardContent } from "@/components/ui/card";
import { TransferStateBadge } from "./TransferStateBadge";
import { formatBytes } from "./FileUpload";

export type TransferRow = {
  id: string;
  status: string;
  created_at: string;
  expires_at: string;
  download_count: number;
  max_downloads: number;
  security_level: string;
  file_metadata?: { original_name: string; size_bytes: number; mime_type: string } | null;
  counterpartyLabel?: string;
};

export function TransferCard({
  transfer,
  direction,
}: {
  transfer: TransferRow;
  direction: "sent" | "received";
}) {
  const meta = transfer.file_metadata;
  return (
    <a href={`/transfer/${transfer.id}`} className="block">
      <Card className="panel transition-colors hover:border-primary/50">
        <CardContent className="flex items-center gap-4 p-4">
          <span className="rounded-md bg-primary/10 p-2.5 text-primary">
            <FileLock2 className="size-5" />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">
              {meta?.original_name ?? "Encrypted payload"}
            </p>
            <p className="text-xs text-muted-foreground">
              {direction === "sent" ? (
                <ArrowUpFromLine className="mr-1 inline size-3" />
              ) : (
                <ArrowDownToLine className="mr-1 inline size-3" />
              )}
              {transfer.counterpartyLabel ?? "—"} ·{" "}
              {meta ? formatBytes(Number(meta.size_bytes)) : "—"} ·{" "}
              {formatDistanceToNow(new Date(transfer.created_at), { addSuffix: true })}
            </p>
          </div>
          <div className="flex flex-col items-end gap-1.5">
            <TransferStateBadge state={transfer.status} />
            <span className="mono text-[11px] text-muted-foreground">
              {transfer.download_count}/{transfer.max_downloads} downloads
            </span>
          </div>
        </CardContent>
      </Card>
    </a>
  );
}
