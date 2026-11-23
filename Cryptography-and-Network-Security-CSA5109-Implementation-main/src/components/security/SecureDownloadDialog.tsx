import { KeyRound, Loader2, Ticket } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/**
 * Receiver-side unlock: one-time access token (server-verified against its SHA-256
 * hash) + key passphrase (PBKDF2 → unwraps the RSA-OAEP private key locally).
 */
export function SecureDownloadDialog({
  open,
  onOpenChange,
  hasKeys,
  busy,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  hasKeys: boolean;
  busy?: boolean;
  onSubmit: (token: string, passphrase: string) => void;
}) {
  const [token, setToken] = useState("");
  const [passphrase, setPassphrase] = useState("");

  return (
    <Dialog open={open} onOpenChange={(v) => (busy ? null : onOpenChange(v))}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Verify &amp; Download</DialogTitle>
          <DialogDescription>
            Two different secrets are required: the one-time transfer access token the sender gave
            you, and your key passphrase which unlocks your RSA private key so the AES-256-GCM
            transfer key can be recovered. SHA-256 is verified before the file is released.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-3">
          <div className="space-y-1.5">
            <Label htmlFor="dl-token" className="flex items-center gap-2">
              <Ticket className="size-3.5" /> One-time access token
            </Label>
            <Input
              id="dl-token"
              className="mono"
              autoComplete="off"
              placeholder="64-character hex token"
              value={token}
              onChange={(e) => setToken(e.target.value.trim())}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="dl-pass" className="flex items-center gap-2">
              <KeyRound className="size-3.5" /> Key passphrase
            </Label>
            <Input
              id="dl-pass"
              type="password"
              autoComplete="current-password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
            />
            {!hasKeys ? (
              <p className="text-xs text-warning">
                No encryption key configured on this account — set one up in Profile → Encryption
                Key Setup first.
              </p>
            ) : null}
          </div>
        </div>

        <DialogFooter>
          <Button variant="ghost" disabled={busy} onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            disabled={!token || !passphrase || busy}
            onClick={() => onSubmit(token, passphrase)}
          >
            {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
            Unlock, verify &amp; download
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
