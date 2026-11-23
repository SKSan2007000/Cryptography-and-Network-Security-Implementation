import { format } from "date-fns";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { TransferStateBadge } from "./TransferStateBadge";
import type { FileMeta, SecurityEventRecord, TransferRecord } from "@/lib/queries";

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-border/60 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className={`break-all text-right text-xs ${mono ? "mono" : "font-medium"}`}>{value}</dd>
    </div>
  );
}

export function SecurityDetailsPanel({
  transfer,
  metadata,
  keyAlgorithm,
  events,
  counterpartyLabel,
  isSender,
}: {
  transfer: TransferRecord;
  metadata: FileMeta | null;
  keyAlgorithm: string | null;
  events: SecurityEventRecord[];
  counterpartyLabel: string;
  isSender: boolean;
}) {
  return (
    <Card className="panel">
      <CardHeader className="pb-2">
        <CardTitle className="flex flex-wrap items-center gap-3 text-sm">
          Security Details
          <TransferStateBadge state={transfer.status} />
          <span className="mono text-[11px] font-normal text-muted-foreground">{transfer.id}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="grid gap-x-8 gap-y-0 sm:grid-cols-2">
        <dl>
          <Row label="File" value={metadata?.original_name ?? "Encrypted payload"} />
          <Row
            label="Size / type"
            value={metadata ? `${metadata.size_bytes} bytes · ${metadata.mime_type}` : "—"}
          />
          <Row label={isSender ? "Receiver" : "Sender"} value={counterpartyLabel} />
          <Row label="Security level" value={transfer.security_level} />
          <Row
            label="Downloads"
            value={`${transfer.download_count}/${transfer.max_downloads} · failed attempts ${transfer.failed_attempts}`}
          />
        </dl>
        <dl>
          <Row label="Encryption" value="AES-256-GCM · 96-bit IV" />
          <Row label="Key wrapping" value={keyAlgorithm ?? "RSA-OAEP-SHA256"} />
          <Row label="IV (base64)" value={transfer.iv} mono />
          <Row
            label="Created"
            value={format(new Date(transfer.created_at), "dd MMM yyyy HH:mm:ss")}
          />
          <Row
            label="Expires"
            value={format(new Date(transfer.expires_at), "dd MMM yyyy HH:mm:ss")}
          />
          <Row
            label="Threat events"
            value={events.length === 0 ? "none detected" : `${events.length} detected`}
          />
        </dl>
      </CardContent>
    </Card>
  );
}
