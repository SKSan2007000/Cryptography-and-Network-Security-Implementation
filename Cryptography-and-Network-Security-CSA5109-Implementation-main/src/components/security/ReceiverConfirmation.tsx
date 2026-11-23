import { CheckCircle2, Loader2, ShieldQuestion, XCircle } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { receiverDecision } from "@/lib/security-lab.functions";

export function ReceiverConfirmation({
  incidentId,
  fileName,
  senderLabel,
  onResolved,
}: {
  incidentId: string;
  fileName: string;
  senderLabel: string;
  onResolved?: (outcome: { decision: string; transferStatus: string }) => void;
}) {
  const [busy, setBusy] = useState<"CONFIRMED" | "DENIED" | null>(null);
  const [done, setDone] = useState<{ decision: string; transferStatus: string } | null>(null);

  async function decide(decision: "CONFIRMED" | "DENIED") {
    setBusy(decision);
    try {
      const res = await receiverDecision({ data: { incidentId, decision } });
      setDone({ decision: res.decision, transferStatus: res.transferStatus });
      onResolved?.({ decision: res.decision, transferStatus: res.transferStatus });
      toast[decision === "CONFIRMED" ? "success" : "error"](
        decision === "CONFIRMED"
          ? "Receiver confirmation recorded."
          : "Receiver denial recorded — transfer terminated.",
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Could not record the confirmation.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card className="panel border-warning/40">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldQuestion className="size-4 text-warning" /> Security verification required
        </CardTitle>
        <CardDescription>
          A suspicious access attempt was detected on this transfer. The intended receiver must
          confirm whether the activity was authorized.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="rounded-md border border-border p-3 text-xs">
          <p>
            <span className="text-muted-foreground">File: </span>
            <span className="mono">{fileName}</span>
          </p>
          <p>
            <span className="text-muted-foreground">Sender: </span>
            <span className="mono">{senderLabel}</span>
          </p>
          <p className="mt-2 font-medium">Did you authorize this transfer?</p>
        </div>
        {done ? (
          <p className="text-xs">
            Recorded <span className="mono">{done.decision}</span> · transfer now{" "}
            <span className="mono">{done.transferStatus}</span>.
          </p>
        ) : (
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={busy !== null} onClick={() => void decide("CONFIRMED")}>
              {busy === "CONFIRMED" ? (
                <Loader2 className="mr-2 size-4 animate-spin" />
              ) : (
                <CheckCircle2 className="mr-2 size-4" />
              )}
              Yes — I authorized it
            </Button>
            <Button
              size="sm"
              variant="destructive"
              disabled={busy !== null}
              onClick={() => void decide("DENIED")}
            >
              {busy === "DENIED" ? (
                <Loader2 className="mr-2 size-4 animate-spin" />
              ) : (
                <XCircle className="mr-2 size-4" />
              )}
              No — this is not authorized
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
