import { cn } from "@/lib/utils";

const TONE: Record<string, string> = {
  info: "bg-info/10 text-info border-info/30",
  low: "bg-secure/10 text-secure border-secure/30",
  medium: "bg-warning/10 text-warning border-warning/30",
  high: "bg-critical/10 text-critical border-critical/30",
  critical: "bg-critical/20 text-critical border-critical/50",
  secure: "bg-secure/10 text-secure border-secure/30",
};

export function ThreatLevelBadge({
  level,
  label,
  className,
}: {
  level: string;
  label?: string;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider",
        TONE[level] ?? TONE["info"],
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" />
      {label ?? level}
    </span>
  );
}
