import { Check } from "lucide-react";

const DEFAULT_ITEMS = [
  "AES-256-GCM protects the file contents and detects tampering.",
  "RSA-OAEP (SHA-256) protects the AES session key so only the receiver can unwrap it.",
  "SHA-256 fingerprints let the receiver prove the file is byte-identical.",
  "HTTPS/TLS protects data in transit between browser, server and storage.",
  "Authentication and role checks control who can open the transfer.",
  "Session, token and access monitoring protects the active transfer.",
  "Audit logs provide traceability for every security-relevant action.",
];

export function SecurityChecklist({
  title = "How this transfer is protected",
  items = DEFAULT_ITEMS,
}: {
  title?: string;
  items?: string[];
}) {
  return (
    <div className="rounded-lg border border-border bg-surface/40 p-4">
      <p className="text-sm font-medium">{title}</p>
      <ul className="mt-3 space-y-2">
        {items.map((item) => (
          <li key={item} className="flex gap-2 text-sm text-muted-foreground">
            <Check className="mt-0.5 size-4 shrink-0 text-secure" />
            <span>{item}</span>
          </li>
        ))}
      </ul>
      <p className="mt-3 text-xs text-muted-foreground">
        Prevention (AES-GCM, RSA-OAEP, TLS) and detection (session, token, integrity and access
        anomalies) are distinct layers. This platform does not claim to detect arbitrary network
        interception.
      </p>
    </div>
  );
}
