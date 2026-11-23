import { AlertOctagon, BellOff, ShieldAlert, Volume2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

export type IncidentAlertData = {
  eventId?: string | undefined;
  transferRef: string;
  fileName: string;
  threat: string;
  severity: string;
  action: string;
  blocked: boolean;
  trustDelta: number;
  simulated: boolean;
};

let sharedCtx: AudioContext | null = null;

function getCtx(): AudioContext | null {
  try {
    const Ctor =
      window.AudioContext ??
      (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
    if (!Ctor) return null;
    sharedCtx ??= new Ctor();
    return sharedCtx;
  } catch {
    return null;
  }
}

/** Schedules one "keen-keen" double chime. */
function scheduleChime(ctx: AudioContext, at: number, strong: boolean) {
  const gap = strong ? 0.14 : 0.18;
  const dur = strong ? 0.16 : 0.2;
  const peak = strong ? 0.6 : 0.48;
  const base = strong ? 1180 : 990;

  [0, 1].forEach((i) => {
    const start = at + i * (dur + gap);
    const osc = ctx.createOscillator();
    const harmonic = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "triangle";
    harmonic.type = "sine";
    osc.frequency.setValueAtTime(base, start);
    harmonic.frequency.setValueAtTime(base * 2, start);
    gain.gain.setValueAtTime(0.0001, start);
    gain.gain.exponentialRampToValueAtTime(peak, start + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, start + dur);
    osc.connect(gain);
    harmonic.connect(gain);
    gain.connect(ctx.destination);
    osc.start(start);
    harmonic.start(start);
    osc.stop(start + dur + 0.02);
    harmonic.stop(start + dur + 0.02);
  });
  return at + 2 * (dur + gap);
}

/** Module-level continuous alarm: one loop at a time, stops only when told to. */
const alarm = {
  key: null as string | null,
  strong: false,
  timer: null as ReturnType<typeof setInterval> | null,
  muted: false,
  async start(key: string, strong: boolean): Promise<boolean> {
    if (this.key === key && this.timer) return true;
    this.stopSound();
    this.key = key;
    this.strong = strong;
    return this.resume();
  },
  async resume(): Promise<boolean> {
    if (!this.key || this.muted || this.timer) return true;
    const ctx = getCtx();
    if (!ctx) return false;
    try {
      if (ctx.state === "suspended") await ctx.resume();
    } catch {
      return false;
    }
    if (ctx.state !== "running") return false;
    const fire = () => {
      const c = getCtx();
      if (c && c.state === "running") scheduleChime(c, c.currentTime + 0.02, this.strong);
    };
    fire();
    this.timer = setInterval(fire, this.strong ? 1400 : 1700);
    return true;
  },
  stopSound() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  },
  stop() {
    this.stopSound();
    this.key = null;
  },
  setMuted(m: boolean) {
    this.muted = m;
    if (m) this.stopSound();
    else void this.resume();
  },
};

export function IncidentAlertOverlay({
  open,
  data,
  onAcknowledge,
  onViewDetails,
  onOpenIncident,
}: {
  open: boolean;
  data: IncidentAlertData | null;
  onAcknowledge: () => void;
  onViewDetails: () => void;
  onOpenIncident?: (() => void) | undefined;
}) {
  const [muted, setMuted] = useState(false);
  const [audioPlayed, setAudioPlayed] = useState<boolean | null>(null);

  const severity = data?.severity?.toLowerCase() ?? "";
  const critical = severity === "critical" || severity === "high";

  // Unlock/resume the AudioContext on the first user interaction with the page.
  useEffect(() => {
    const unlock = () => {
      const ctx = getCtx();
      if (ctx && ctx.state === "suspended") void ctx.resume().then(() => alarm.resume());
      else void alarm.resume();
    };
    window.addEventListener("pointerdown", unlock);
    window.addEventListener("keydown", unlock);
    return () => {
      window.removeEventListener("pointerdown", unlock);
      window.removeEventListener("keydown", unlock);
    };
  }, []);

  const alertKey = data
    ? (data.eventId ?? `${data.transferRef}|${data.threat}|${data.action}|${data.severity}`)
    : null;

  // Start the continuous alarm once per incident; re-renders never restart it.
  useEffect(() => {
    if (!open || !alertKey) return;
    let cancelled = false;
    void alarm.start(alertKey, critical).then((ok) => {
      if (!cancelled) setAudioPlayed(ok);
    });
    return () => {
      cancelled = true;
    };
  }, [open, alertKey, critical]);

  useEffect(() => {
    alarm.setMuted(muted);
  }, [muted]);

  const acknowledge = () => {
    alarm.stop();
    onAcknowledge();
  };

  if (!data) return null;

  const Field = ({
    label,
    value,
    tone,
  }: {
    label: string;
    value: string;
    tone?: string | undefined;
  }) => (
    <div className="rounded-md border border-border/70 bg-background/60 p-3">
      <p className="text-[10px] uppercase tracking-[0.14em] text-muted-foreground">{label}</p>
      <p className={cn("mono mt-1 text-sm font-semibold", tone)}>{value}</p>
    </div>
  );

  return (
    <Dialog open={open} onOpenChange={(v) => (!v ? onAcknowledge() : undefined)}>
      <DialogContent
        className={cn(
          "max-w-2xl border-2",
          critical ? "border-critical/70 bg-critical/5" : "border-warning/70 bg-warning/5",
        )}
      >
        <div className="flex items-start gap-3">
          <span
            className={cn(
              "flex size-11 shrink-0 items-center justify-center rounded-md",
              critical ? "bg-critical/15 text-critical" : "bg-warning/15 text-warning",
            )}
            aria-hidden
          >
            <AlertOctagon className="size-6" />
          </span>
          <div className="min-w-0">
            <DialogTitle className="text-lg font-semibold tracking-tight">
              SECURITY INCIDENT DETECTED
            </DialogTitle>
            <DialogDescription className="text-sm">
              Secure transfer interrupted — automatic security response activated.
            </DialogDescription>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {data.simulated ? (
                <Badge variant="outline" className="border-warning/60 text-warning">
                  SECURITY LAB SIMULATION
                </Badge>
              ) : null}
              <Badge variant="outline" className="mono">
                {data.transferRef}
              </Badge>
            </div>
          </div>
        </div>

        <div
          role="alert"
          aria-live="assertive"
          className="rounded-md border border-border/70 bg-background/60 p-3 text-sm"
        >
          Security alert. Unauthorized transfer activity detected. The secure transfer has been
          interrupted.
        </div>

        <div className="grid gap-2 sm:grid-cols-3">
          <Field label="Threat" value={data.threat.replace(/_/g, " ")} />
          <Field
            label="Severity"
            value={data.severity.toUpperCase()}
            tone={critical ? "text-critical" : "text-warning"}
          />
          <Field label="File" value={data.fileName} />
          <Field label="Action" value={data.action.replace(/_/g, " ")} />
          <Field
            label="Access"
            value={data.blocked ? "BLOCKED" : "RECORDED"}
            tone={data.blocked ? "text-critical" : undefined}
          />
          <Field
            label="Trust impact"
            value={`${data.trustDelta}`}
            tone={data.trustDelta < 0 ? "text-critical" : undefined}
          />
        </div>

        <p className="text-xs text-muted-foreground">
          {audioPlayed === false
            ? "Audio alarm blocked by the browser — click anywhere on this page to enable sound."
            : muted
              ? "Audio alarm muted. Visual alert remains active; unmute to resume the alarm."
              : "Continuous audio alarm active — it repeats until you acknowledge this incident."}
        </p>

        <div className="flex flex-wrap gap-2">
          <Button onClick={acknowledge} variant="destructive">
            <ShieldAlert className="mr-2 size-4" /> Acknowledge &amp; stop alarm
          </Button>

          <Button onClick={onViewDetails} variant="outline">
            View security details
          </Button>
          {onOpenIncident ? (
            <Button onClick={onOpenIncident} variant="outline">
              Open incident
            </Button>
          ) : null}
          <Button
            onClick={() => setMuted((m) => !m)}
            variant="ghost"
            size="sm"
            className="ml-auto"
            aria-pressed={muted}
          >
            {muted ? <Volume2 className="mr-2 size-4" /> : <BellOff className="mr-2 size-4" />}
            {muted ? "Unmute alarm" : "Mute alarm"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
