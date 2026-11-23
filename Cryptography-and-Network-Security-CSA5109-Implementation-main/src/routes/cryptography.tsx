import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { AlgorithmInfo } from "@/components/security/AlgorithmInfo";
import { SecurityChecklist } from "@/components/security/SecurityChecklist";
import { CRYPTO_PARAMS } from "@/lib/crypto";

export const Route = createFileRoute("/cryptography")({
  head: () => ({
    meta: [
      { title: "Cryptography — SentinelCrypt" },
      {
        name: "description",
        content:
          "How SentinelCrypt protects files: AES-256-GCM, RSA-OAEP 2048 key wrapping, PBKDF2 key protection and SHA-256 integrity — all via the Web Crypto API.",
      },
      { property: "og:title", content: "Cryptography — SentinelCrypt" },
      {
        property: "og:description",
        content:
          "AES-256-GCM · RSA-OAEP 2048 · PBKDF2 · SHA-256 — standard algorithms only, executed client-side.",
      },
      { property: "og:type", content: "website" },
    ],
  }),
  component: CryptographyPage,
});

const PIPELINE = [
  {
    step: "1",
    title: "SHA-256 fingerprint",
    body: "The plaintext is hashed in the browser. This 256-bit digest is the integrity contract for the whole transfer.",
  },
  {
    step: "2",
    title: "AES-256-GCM encryption",
    body: `A fresh ${CRYPTO_PARAMS.aes.length}-bit AES key and a random ${CRYPTO_PARAMS.aes.ivBytes * 8}-bit IV encrypt the file. GCM provides confidentiality and authenticity — any tampering breaks decryption.`,
  },
  {
    step: "3",
    title: "RSA-OAEP key wrapping",
    body: "The AES key is wrapped with the receiver's RSA-OAEP 2048 public key (SHA-256). Only the receiver's private key can unwrap it; the server stores only the wrapped form.",
  },
  {
    step: "4",
    title: "Protected private keys",
    body: `Each user's RSA private key is stored wrapped with a key derived from their passphrase via PBKDF2 (${CRYPTO_PARAMS.kdf.iterations.toLocaleString()} iterations, SHA-256). The passphrase never leaves the browser.`,
  },
  {
    step: "5",
    title: "Verified delivery",
    body: "The receiver unwraps the AES key, decrypts, recomputes SHA-256 and the server compares it to the sender's fingerprint before releasing the file. A mismatch raises an INTEGRITY_FAILURE incident.",
  },
];

function CryptographyPage() {
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex w-full max-w-5xl items-center justify-between px-4 py-5">
        <Button variant="ghost" asChild>
          <Link to="/">
            <ArrowLeft className="mr-1.5 size-4" /> SentinelCrypt
          </Link>
        </Button>
        <Button asChild>
          <Link to="/register">Get started</Link>
        </Button>
      </header>

      <main className="mx-auto w-full max-w-5xl space-y-10 px-4 pb-16">
        <section className="pt-6">
          <p className="mono text-xs uppercase tracking-widest text-primary">
            Faculty cryptography view
          </p>
          <h1 className="mt-3 text-3xl font-semibold tracking-tight sm:text-4xl">
            Standard algorithms. No custom primitives.
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            Every cryptographic operation runs in the browser through the Web Crypto API. The server
            only ever handles ciphertext, wrapped keys and hashes — it cannot read file contents.
          </p>
        </section>

        <section className="space-y-3">
          {PIPELINE.map((p) => (
            <Card key={p.step} className="panel">
              <CardContent className="flex gap-4 p-4">
                <span className="mono grid size-8 shrink-0 place-items-center rounded-md bg-primary/15 text-sm font-semibold text-primary">
                  {p.step}
                </span>
                <div>
                  <p className="text-sm font-medium">{p.title}</p>
                  <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{p.body}</p>
                </div>
              </CardContent>
            </Card>
          ))}
        </section>

        <div className="grid gap-4 lg:grid-cols-2">
          <AlgorithmInfo defaultOpen />
          <SecurityChecklist />
        </div>

        <Card className="panel">
          <CardHeader>
            <CardTitle className="text-sm">Threat model & trust engine</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-xs leading-relaxed text-muted-foreground">
            <p>
              Beyond encryption, a rule-based threat engine watches sessions, tokens and integrity
              outcomes. Detected anomalies (token replay, integrity failure, device change,
              suspicious IP shifts, abnormal request rates) map to transparent trust-score deltas
              between −5 and −50 and response actions ranging from logging to transfer termination
              and session revocation.
            </p>
            <p>
              Accounts start at a trust score of 100. Scores below thresholds progressively restrict
              downloads, and every decision is written to an immutable audit log visible to the
              account owner and administrators.
            </p>
          </CardContent>
        </Card>

        <div className="flex justify-center">
          <Button asChild>
            <Link to="/register">
              Create an account <ArrowRight className="ml-2 size-4" />
            </Link>
          </Button>
        </div>
      </main>
    </div>
  );
}
