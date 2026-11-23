import { CheckCircle2, KeyRound, Loader2, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { CRYPTO_PARAMS } from "@/lib/crypto";
import { provisionKeys, type KeyRecord } from "@/lib/keyvault";

/**
 * Profile → Security → Encryption Key Setup.
 *
 * The passphrase never leaves the browser and is never persisted: it only feeds
 * PBKDF2 (SHA-256, 250k iterations) to derive the AES-GCM key-encryption key that
 * wraps the RSA-OAEP private key at rest. It cannot be displayed or recovered.
 */
export function EncryptionKeySetup({
  userId,
  keyRecord,
  onProvisioned,
}: {
  userId: string;
  keyRecord: KeyRecord | null;
  onProvisioned: (record: KeyRecord) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);

  const configured = Boolean(keyRecord);
  const tooShort = pass.length > 0 && pass.length < 10;
  const mismatch = confirm.length > 0 && confirm !== pass;
  const canSubmit = pass.length >= 10 && confirm === pass && ack && !busy;

  async function submit() {
    if (!canSubmit) return;
    setBusy(true);
    try {
      const record = await provisionKeys(userId, pass);
      onProvisioned(record);
      setOpen(false);
      setPass("");
      setConfirm("");
      setAck(false);
      toast.success("RSA-OAEP 2048 key pair published and protected with your key passphrase.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Key setup failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card className="panel">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm">
          <KeyRound className="size-4 text-primary" /> Encryption Key Setup
          <Badge variant={configured ? "default" : "destructive"} className="ml-1">
            {configured ? "Configured" : "Not configured"}
          </Badge>
        </CardTitle>
        <CardDescription>
          <strong>
            Key Passphrase protects your RSA private key. It is different from your one-time
            transfer access token.
          </strong>{" "}
          It is never stored, transmitted or recoverable — it only derives (PBKDF2-SHA256,{" "}
          {CRYPTO_PARAMS.kdf.iterations.toLocaleString()} iterations) the AES-GCM key that wraps
          your private key at rest. You need it to receive and decrypt files.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {configured ? (
          <p className="mono flex items-center gap-2 text-xs text-muted-foreground">
            <CheckCircle2 className="size-4 text-success" />
            {keyRecord?.algorithm} · private key wrapped with your passphrase
          </p>
        ) : (
          <p className="flex items-center gap-2 text-xs text-warning">
            <ShieldAlert className="size-4" />
            No encryption key yet — others cannot send you files and you cannot decrypt downloads.
          </p>
        )}

        <Button variant={configured ? "outline" : "default"} onClick={() => setOpen(true)}>
          <KeyRound className="mr-2 size-4" />
          {configured ? "Rotate key pair & passphrase" : "Create key passphrase & generate keys"}
        </Button>

        <Dialog open={open} onOpenChange={(v) => (busy ? null : setOpen(v))}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>
                {configured ? "Rotate encryption keys" : "Create your key passphrase"}
              </DialogTitle>
              <DialogDescription>
                Key Passphrase protects your RSA private key. It is different from your one-time
                transfer access token, and different from your account password. We cannot show or
                reset it — losing it means losing access to files sent to you.
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3">
              <div className="space-y-1.5">
                <Label htmlFor="kp">Key passphrase (min 10 characters)</Label>
                <Input
                  id="kp"
                  type="password"
                  autoComplete="new-password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                />
                {tooShort ? (
                  <p className="text-xs text-destructive">Use at least 10 characters.</p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="kp2">Confirm key passphrase</Label>
                <Input
                  id="kp2"
                  type="password"
                  autoComplete="new-password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                />
                {mismatch ? (
                  <p className="text-xs text-destructive">Passphrases do not match.</p>
                ) : null}
              </div>
              <label className="flex items-start gap-2 text-xs text-muted-foreground">
                <input
                  type="checkbox"
                  checked={ack}
                  onChange={(e) => setAck(e.target.checked)}
                  className="mt-0.5 accent-current"
                />
                I understand this passphrase cannot be recovered
                {configured
                  ? ", and that rotating keys invalidates in-flight transfers sent to me."
                  : "."}
              </label>
            </div>

            <DialogFooter>
              <Button variant="ghost" disabled={busy} onClick={() => setOpen(false)}>
                Cancel
              </Button>
              <Button disabled={!canSubmit} onClick={() => void submit()}>
                {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
                {configured ? "Rotate keys" : "Generate protected key pair"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
