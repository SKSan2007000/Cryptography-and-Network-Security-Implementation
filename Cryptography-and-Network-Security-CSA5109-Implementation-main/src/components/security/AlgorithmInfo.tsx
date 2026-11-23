import { ChevronDown } from "lucide-react";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { CRYPTO_PARAMS } from "@/lib/crypto";

const ROWS = [
  [
    "Confidentiality",
    `AES-${CRYPTO_PARAMS.aes.length}-GCM, ${CRYPTO_PARAMS.aes.ivBytes * 8}-bit random IV, ${CRYPTO_PARAMS.aes.tagBits}-bit auth tag`,
  ],
  [
    "Key wrapping",
    `RSA-OAEP ${CRYPTO_PARAMS.rsa.modulusLength}-bit with ${CRYPTO_PARAMS.rsa.hash}`,
  ],
  ["Integrity", "SHA-256 fingerprint of plaintext and of the ciphertext payload"],
  [
    "Private key at rest",
    `PBKDF2-${CRYPTO_PARAMS.kdf.hash}, ${CRYPTO_PARAMS.kdf.iterations.toLocaleString()} iterations, AES-GCM wrapped`,
  ],
  ["Transport", "HTTPS/TLS between browser, application server and object storage"],
  ["Implementation", "Web Crypto API only — no custom cryptographic primitives"],
];

export function AlgorithmInfo({ defaultOpen = false }: { defaultOpen?: boolean }) {
  return (
    <Collapsible
      defaultOpen={defaultOpen}
      className="rounded-lg border border-border bg-surface/40"
    >
      <CollapsibleTrigger className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium">
        Security details (academic view)
        <ChevronDown className="size-4 text-muted-foreground" />
      </CollapsibleTrigger>
      <CollapsibleContent className="space-y-2 border-t border-border px-4 py-3">
        {ROWS.map(([label, value]) => (
          <div key={label} className="grid gap-1 sm:grid-cols-[10rem_1fr]">
            <span className="text-xs font-medium text-muted-foreground">{label}</span>
            <span className="mono text-xs">{value}</span>
          </div>
        ))}
      </CollapsibleContent>
    </Collapsible>
  );
}
