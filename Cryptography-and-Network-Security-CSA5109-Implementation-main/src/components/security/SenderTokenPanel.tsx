import { Check, Copy, Eye, EyeOff, KeyRound, ShieldAlert } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { rsaOpenText } from "@/lib/crypto";
import { getPrivateKey } from "@/lib/keyvault";

/**
 * Sender-only view of the one-time access token.
 *
 * The token is never stored in plaintext: at creation it is sealed with the
 * sender's own RSA-OAEP public key. Revealing it requires the sender's key
 * passphrase, unwrapping their private key in the browser.
 */
export function SenderTokenPanel({
  userId,
  sealedToken,
}: {
  userId: string;
  sealedToken: string | null;
}) {
  const [token, setToken] = useState<string | null>(null);
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  async function reveal() {
    if (token) {
      setVisible(true);
      return;
    }
    const passphrase = window.prompt("Enter your key passphrase to reveal the access token:");
    if (!passphrase) return;
    setBusy(true);
    try {
      const privateKey = await getPrivateKey(userId, passphrase);
      setToken(await rsaOpenText(privateKey, sealedToken!));
      setVisible(true);
    } catch {
      toast.error("Could not unlock the token — check your key passphrase.");
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    let value = token;
    if (!value) {
      const passphrase = window.prompt("Enter your key passphrase to copy the access token:");
      if (!passphrase) return;
      setBusy(true);
      try {
        const privateKey = await getPrivateKey(userId, passphrase);
        value = await rsaOpenText(privateKey, sealedToken!);
        setToken(value);
      } catch {
        toast.error("Could not unlock the token — check your key passphrase.");
        return;
      } finally {
        setBusy(false);
      }
    }
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
    toast.success("Access token copied to clipboard.");
  }

  return (
    <Card className="panel">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <KeyRound className="size-4" /> Secure Access
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          One-Time Access Token
        </p>

        {sealedToken ? (
          <>
            <div className="flex items-center gap-2">
              <code className="mono flex-1 truncate rounded-md border border-border bg-muted/40 px-3 py-2 text-xs">
                {visible && token ? token : "••••••••••••••••••••••••"}
              </code>
              <Button variant="outline" size="sm" disabled={busy} onClick={() => void copy()}>
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
                <span className="ml-1.5">Copy</span>
              </Button>
            </div>
            <Button
              variant="secondary"
              size="sm"
              disabled={busy}
              onClick={() => (visible ? setVisible(false) : void reveal())}
            >
              {visible ? (
                <>
                  <EyeOff className="mr-1.5 size-4" /> Hide Token
                </>
              ) : (
                <>
                  <Eye className="mr-1.5 size-4" /> Show Token
                </>
              )}
            </Button>
          </>
        ) : (
          <p className="text-xs text-muted-foreground">
            This transfer was created before sealed-token recovery was available, so the token
            cannot be shown again. Create a new transfer to get a recoverable token.
          </p>
        )}

        <div className="flex items-start gap-2 rounded-md border border-destructive/40 bg-destructive/10 p-3">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
          <p className="text-xs text-destructive">
            This token authorizes access to this specific transfer. Share it only with the intended
            receiver.
          </p>
        </div>
        <p className="text-[11px] text-muted-foreground">
          Sealed with your RSA-OAEP public key — never stored in plaintext, never placed in the URL
          and never written to audit logs. Expiry and replay protection remain enforced server-side.
        </p>
      </CardContent>
    </Card>
  );
}
