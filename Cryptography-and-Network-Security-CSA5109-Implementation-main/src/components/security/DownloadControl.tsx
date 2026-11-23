import { Download, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";

export function DownloadControl({
  fileName,
  disabled,
  disabledReason,
  remaining,
  busy,
  onDownload,
}: {
  fileName: string;
  disabled?: boolean;
  disabledReason?: string | null;
  remaining: number;
  busy?: boolean;
  onDownload: () => void;
}) {
  return (
    <div className="space-y-2">
      <Button className="w-full" disabled={disabled || busy} onClick={onDownload}>
        {busy ? (
          <Loader2 className="mr-2 size-4 animate-spin" />
        ) : (
          <Download className="mr-2 size-4" />
        )}
        {busy ? "Verifying…" : `Verify & Download ${fileName}`}
      </Button>
      <p className="text-center text-[11px] text-muted-foreground">
        {disabled && disabledReason
          ? disabledReason
          : `${remaining} download${remaining === 1 ? "" : "s"} remaining · SHA-256 checked before release`}
      </p>
    </div>
  );
}
