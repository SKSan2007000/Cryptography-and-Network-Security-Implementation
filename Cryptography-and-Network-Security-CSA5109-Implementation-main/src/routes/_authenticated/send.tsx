import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Globe,
  KeyRound,
  Loader2,
  MapPin,
  Send as SendIcon,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { FileUpload, formatBytes } from "@/components/security/FileUpload";
import { ReceiverSelector, type Receiver } from "@/components/security/ReceiverSelector";
import { SecurityChecklist } from "@/components/security/SecurityChecklist";
import { TransferProgress, type Step } from "@/components/security/TransferProgress";
import { useAuth } from "@/hooks/useAuth";
import { getKeyRecord, provisionKeys } from "@/lib/keyvault";
import { getTrustStatus, isTransferEligible, type TrustStatus } from "@/lib/security-rules";
import { SEND_STEPS, sendSecureTransfer, type SendStepKey } from "@/lib/transfer-client";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_authenticated/send")({
  head: () => ({
    meta: [
      { title: "Secure Transfer — SentinelCrypt" },
      {
        name: "description",
        content:
          "Encrypt a file client-side with AES-256-GCM and send it with RSA-OAEP key protection, SHA-256 verification and trust evaluation.",
      },
    ],
  }),
  component: SendPage,
});

const EXPIRY_OPTIONS = [
  { label: "1 hour", hours: 1 },
  { label: "6 hours", hours: 6 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 168 },
];

const DOWNLOAD_OPTIONS = [1, 3, 5, 10];

function initialSteps(): Step[] {
  return SEND_STEPS.map((s) => ({ key: s.key, label: s.label, status: "pending" as const }));
}

function SendPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [receiver, setReceiver] = useState<string | null>(null);
  const [selectedReceiverObj, setSelectedReceiverObj] = useState<Receiver | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [expiry, setExpiry] = useState("24");
  const [limit, setLimit] = useState("1");
  const [steps, setSteps] = useState<Step[]>(initialSteps);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ transferId: string; token: string } | null>(null);
  const [ensuringKeys, setEnsuringKeys] = useState(false);

  // Consent-based location state
  const [allowLocation, setAllowLocation] = useState(false);
  const [capturingLocation, setCapturingLocation] = useState(false);
  const [locationCoords, setLocationCoords] = useState<{
    latitude: number;
    longitude: number;
    timestamp: string;
  } | null>(null);
  const [locationMessage, setLocationMessage] = useState<string | null>(null);

  const receiverTrustScore = selectedReceiverObj?.trust_score ?? 100;
  const receiverTrustStatus: TrustStatus = getTrustStatus(receiverTrustScore);
  const isEligible = isTransferEligible(receiverTrustScore);

  const ready = Boolean(
    receiver &&
    file &&
    !sending &&
    isEligible &&
    selectedReceiverObj?.hasKey &&
    selectedReceiverObj?.status === "active",
  );

  const setStep = (key: SendStepKey, status: Step["status"], detail?: string) =>
    setSteps((prev) =>
      prev.map((s) => (s.key === key ? { ...s, status, ...(detail ? { detail } : {}) } : s)),
    );

  const expiryLabel = useMemo(
    () => EXPIRY_OPTIONS.find((o) => String(o.hours) === expiry)?.label ?? `${expiry} hours`,
    [expiry],
  );

  async function handleLocationToggle(checked: boolean) {
    setAllowLocation(checked);
    setLocationMessage(null);
    if (!checked) {
      setLocationCoords(null);
      return;
    }

    if (!navigator.geolocation) {
      setLocationMessage(
        "Geolocation is not supported by this browser. Transfer can continue without location.",
      );
      return;
    }

    setCapturingLocation(true);
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        setCapturingLocation(false);
        const coords = {
          latitude: Number(pos.coords.latitude.toFixed(6)),
          longitude: Number(pos.coords.longitude.toFixed(6)),
          timestamp: new Date(pos.timestamp).toISOString(),
        };
        setLocationCoords(coords);
        setLocationMessage(
          `Location captured · Latitude: ${coords.latitude.toFixed(4)}, Longitude: ${coords.longitude.toFixed(4)}`,
        );
        toast.success("Consented location captured for Security Digital Twin visualization.");
      },
      (err) => {
        setCapturingLocation(false);
        setLocationCoords(null);
        setLocationMessage(
          "Location permission was not granted. Transfer can continue without location.",
        );
        toast.info("Location permission was not granted. Transfer can continue without location.");
      },
      { enableHighAccuracy: false, timeout: 8000, maximumAge: 60000 },
    );
  }

  async function handleSend() {
    if (!user || !receiver || !file) return;
    if (!isEligible) {
      setError(
        "Transfer blocked because the selected receiver has a Trust Score below the required threshold of 60.",
      );
      return;
    }

    setSending(true);
    setError(null);
    setSteps(initialSteps());
    try {
      const created = await sendSecureTransfer({
        file,
        recipientId: receiver,
        senderId: user.id,
        expiresInHours: Number(expiry),
        maxDownloads: Number(limit),
        securityLevel: "standard",
        senderLatitude: locationCoords?.latitude ?? null,
        senderLongitude: locationCoords?.longitude ?? null,
        senderLocationTimestamp: locationCoords?.timestamp ?? null,
        onStep: setStep,
      });
      setResult(created);
      toast.success("Secure transfer created and monitored.");
    } catch (e) {
      const message = e instanceof Error ? e.message : "The transfer could not be completed.";
      setError(message);
    } finally {
      setSending(false);
    }
  }

  async function handleProvisionKeys() {
    if (!user) return;
    setEnsuringKeys(true);
    try {
      const existing = await getKeyRecord(user.id);
      if (existing) {
        toast.info("Your RSA key pair is already published.");
        return;
      }
      const passphrase = window.prompt(
        "Create a key passphrase to protect your RSA private key (PBKDF2-wrapped). Keep it safe.",
      );
      if (!passphrase || passphrase.length < 8) {
        toast.error("Passphrase must be at least 8 characters.");
        return;
      }
      await provisionKeys(user.id, passphrase);
      toast.success("RSA-OAEP 2048 key pair published. Others can now send you files.");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Key setup failed.");
    } finally {
      setEnsuringKeys(false);
    }
  }

  if (result) {
    return (
      <AppShell title="Transfer Sent" description="Your encrypted payload is stored and monitored.">
        <Card className="panel">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ShieldCheck className="size-5 text-secure" /> Transfer created
            </CardTitle>
            <CardDescription>
              Share this one-time token with the recipient through a separate channel.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface/60 p-3">
              <code className="mono flex-1 break-all text-sm">{result.token}</code>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void navigator.clipboard.writeText(result.token);
                  toast.success("Token copied");
                }}
              >
                <Copy className="mr-1.5 size-3.5" /> Copy
              </Button>
            </div>
            <TransferProgress steps={steps} />
            <div className="flex gap-2">
              <Button asChild>
                <Link to="/transfer/$id" params={{ id: result.transferId }}>
                  View transfer
                </Link>
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setResult(null);
                  setFile(null);
                  setReceiver(null);
                  setSelectedReceiverObj(null);
                  setLocationCoords(null);
                  setLocationMessage(null);
                  setAllowLocation(false);
                  setSteps(initialSteps());
                }}
              >
                Send another
              </Button>
            </div>
          </CardContent>
        </Card>
      </AppShell>
    );
  }

  return (
    <AppShell
      title="Secure Transfer"
      description="Encrypt in your browser, then transfer. The server only ever stores ciphertext."
    >
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          {/* Step 1: Select Receiver */}
          <Card className="panel">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Step 1 — Select Receiver</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <ReceiverSelector
                currentUserId={user?.id}
                value={receiver}
                onChange={setReceiver}
                onSelectReceiver={setSelectedReceiverObj}
                disabled={sending}
              />
              <Button
                variant="link"
                size="sm"
                className="px-0"
                onClick={handleProvisionKeys}
                disabled={ensuringKeys}
              >
                {ensuringKeys ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : null}
                Publish / check my own RSA key pair
              </Button>

              {/* Receiver Trust Score & Eligibility Check */}
              {selectedReceiverObj ? (
                <div
                  className={cn(
                    "rounded-lg border p-3.5 text-sm transition-all",
                    isEligible
                      ? "border-secure/40 bg-secure/5"
                      : "border-critical/60 bg-critical/10",
                  )}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div>
                      <p className="font-semibold text-foreground">
                        Receiver: {selectedReceiverObj.full_name ?? selectedReceiverObj.email}
                      </p>
                      <div className="mt-1 flex items-center gap-2 text-xs">
                        <span className="mono">
                          Trust Score: <strong>{receiverTrustScore}</strong> / 100
                        </span>
                        <Badge
                          variant="outline"
                          className={cn(
                            "text-[10px]",
                            receiverTrustStatus === "TRUSTED" && "border-secure/50 text-secure",
                            receiverTrustStatus === "NORMAL" && "border-primary/50 text-primary",
                            receiverTrustStatus === "CAUTION" && "border-warning/50 text-warning",
                            receiverTrustStatus === "HIGH RISK" &&
                              "border-critical/50 text-critical",
                          )}
                        >
                          {receiverTrustStatus}
                        </Badge>
                      </div>
                    </div>

                    <div>
                      {isEligible ? (
                        <Badge
                          variant="outline"
                          className="border-secure/50 bg-secure/10 text-secure py-1 px-2.5"
                        >
                          <CheckCircle2 className="mr-1.5 size-3.5" /> Transfer Allowed
                        </Badge>
                      ) : (
                        <Badge variant="destructive" className="py-1 px-2.5">
                          <AlertTriangle className="mr-1.5 size-3.5" /> Transfer Blocked
                        </Badge>
                      )}
                    </div>
                  </div>

                  {!isEligible ? (
                    <p className="mt-2.5 text-xs text-critical leading-relaxed font-medium">
                      ⚠ This receiver does not currently meet the minimum trust requirement of 60.
                      Transfer creation is blocked by the security policy.
                    </p>
                  ) : null}
                </div>
              ) : null}
            </CardContent>
          </Card>

          {/* Step 2: Consent-Based Location Capture */}
          <Card className="panel">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <MapPin className="size-4 text-primary" /> Step 2 — Transfer Location
                (Consent-Based)
              </CardTitle>
              <CardDescription>
                Location is used as a contextual security signal and to visualize transfer activity
                in the Security Digital Twin.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-start space-x-2.5 pt-1">
                <Checkbox
                  id="consent-location"
                  checked={allowLocation}
                  onCheckedChange={(c) => void handleLocationToggle(Boolean(c))}
                  disabled={sending}
                />
                <div className="grid gap-1.5 leading-none">
                  <label
                    htmlFor="consent-location"
                    className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer"
                  >
                    Use my location for this transfer
                  </label>
                  <p className="text-xs text-muted-foreground">
                    Captures your current device coordinates only for this transfer event. No
                    continuous tracking.
                  </p>
                </div>
              </div>

              {capturingLocation ? (
                <p className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <Loader2 className="size-3.5 animate-spin text-primary" /> Requesting location
                  permission…
                </p>
              ) : null}

              {locationCoords ? (
                <div className="rounded-md border border-secure/40 bg-secure/5 p-2.5 text-xs flex items-center justify-between">
                  <span className="text-secure flex items-center gap-1.5 font-medium">
                    <CheckCircle2 className="size-3.5" /> User-consented device location captured
                  </span>
                  <span className="mono text-muted-foreground">
                    {locationCoords.latitude.toFixed(4)}, {locationCoords.longitude.toFixed(4)}
                  </span>
                </div>
              ) : locationMessage ? (
                <p className="text-xs text-muted-foreground italic">{locationMessage}</p>
              ) : null}
            </CardContent>
          </Card>

          {/* Step 3: Upload File */}
          <Card className="panel">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Step 3 — Upload File</CardTitle>
              {file ? (
                <CardDescription>
                  {file.name} · {formatBytes(file.size)} · {file.type || "application/octet-stream"}
                </CardDescription>
              ) : null}
            </CardHeader>
            <CardContent>
              <FileUpload file={file} onSelect={setFile} disabled={sending} />
            </CardContent>
          </Card>

          {/* Step 4: Security Settings */}
          <Card className="panel">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Step 4 — Security Settings</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="expiry">Expiry</Label>
                <Select value={expiry} onValueChange={setExpiry} disabled={sending}>
                  <SelectTrigger id="expiry">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {EXPIRY_OPTIONS.map((o) => (
                      <SelectItem key={o.hours} value={String(o.hours)}>
                        {o.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="limit">Download limit</Label>
                <Select value={limit} onValueChange={setLimit} disabled={sending}>
                  <SelectTrigger id="limit">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DOWNLOAD_OPTIONS.map((n) => (
                      <SelectItem key={n} value={String(n)}>
                        {n} {n === 1 ? "download" : "downloads"}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Step 5: Security Preview */}
          <Card className="panel">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Step 5 — Security Preview</CardTitle>
              <CardDescription>
                {file
                  ? `${file.name} will be encrypted with AES-256-GCM, its key wrapped with the receiver's RSA-OAEP 2048 public key, fingerprinted with SHA-256, and transferred over HTTPS/TLS. Expires in ${expiryLabel}, ${limit} download${limit === "1" ? "" : "s"} allowed.`
                  : "Select a file to preview its protection."}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <SecurityChecklist title="Protection applied to this transfer" />
            </CardContent>
          </Card>
        </div>

        {/* Step 6: Secure Send Card */}
        <Card className="panel h-fit">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Step 6 — Secure Send</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {error ? (
              <p className="rounded-md border border-critical/40 bg-critical/5 p-3 text-sm text-critical">
                {error}
              </p>
            ) : null}
            <TransferProgress steps={steps} />
            <Button
              className="w-full"
              disabled={!ready}
              variant={!isEligible && receiver ? "destructive" : "default"}
              onClick={() => void handleSend()}
            >
              {sending ? (
                <Loader2 className="mr-2 size-4 animate-spin" />
              ) : (
                <SendIcon className="mr-2 size-4" />
              )}
              {sending
                ? "Sending…"
                : !isEligible && receiver
                  ? "Transfer Blocked (High Risk)"
                  : "Encrypt & Send"}
            </Button>
            <Button
              variant="outline"
              className="w-full"
              onClick={() => void navigate({ to: "/dashboard" })}
              disabled={sending}
            >
              Cancel
            </Button>
          </CardContent>
        </Card>
      </div>
    </AppShell>
  );
}
