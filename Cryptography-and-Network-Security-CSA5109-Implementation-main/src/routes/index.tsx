import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, FileLock2, Fingerprint, KeyRound, Lock, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { EncryptionStatus } from "@/components/security/EncryptionStatus";
import { SecurityChecklist } from "@/components/security/SecurityChecklist";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "SentinelCrypt — Trust-Aware Secure File Transfer" },
      {
        name: "description",
        content:
          "SentinelCrypt is a trust-aware secure file transfer platform: client-side AES-256-GCM encryption, RSA-OAEP key wrapping, SHA-256 integrity verification and a transparent trust-score engine.",
      },
      { property: "og:title", content: "SentinelCrypt — Trust-Aware Secure File Transfer" },
      {
        property: "og:description",
        content:
          "Trust every transfer. Verify every byte. Client-side encryption with full audit and threat detection.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Landing,
});

function Landing() {
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex w-full max-w-6xl items-center justify-between px-4 py-5">
        <div className="flex items-center gap-2.5">
          <span className="rounded-md bg-primary/15 p-2 text-primary">
            <ShieldCheck className="size-5" />
          </span>
          <span className="text-sm font-semibold tracking-tight">SentinelCrypt</span>
        </div>
        <nav className="flex items-center gap-2">
          <Button variant="ghost" asChild>
            <Link to="/auth">Sign in</Link>
          </Button>
          <Button asChild>
            <Link to="/register">Create account</Link>
          </Button>
        </nav>
      </header>

      <main className="mx-auto w-full max-w-6xl px-4 pb-16">
        <section className="py-14 text-center sm:py-20">
          <p className="mono text-xs uppercase tracking-widest text-primary">
            Trust-Aware Secure File Transfer Platform
          </p>
          <h1 className="mx-auto mt-4 max-w-3xl text-4xl font-semibold tracking-tight sm:text-5xl">
            Trust Every Transfer. Verify Every Byte.
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-sm leading-relaxed text-muted-foreground sm:text-base">
            Files never leave your browser unencrypted. SentinelCrypt applies AES-256-GCM
            client-side, wraps the session key with the recipient's RSA-OAEP 2048 public key, and
            proves delivery with a SHA-256 fingerprint — while a transparent trust-score engine
            watches sessions, tokens and integrity in real time.
          </p>
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
            <Button size="lg" asChild>
              <Link to="/register">
                Start transferring securely <ArrowRight className="ml-2 size-4" />
              </Link>
            </Button>
            <Button size="lg" variant="outline" asChild>
              <Link to="/cryptography">See the cryptography</Link>
            </Button>
          </div>
        </section>

        <EncryptionStatus />

        <section className="mt-12 grid gap-4 md:grid-cols-4">
          {[
            {
              icon: Lock,
              title: "AES-256-GCM",
              body: "Authenticated encryption with a fresh random key and 96-bit IV per transfer.",
            },
            {
              icon: KeyRound,
              title: "RSA-OAEP 2048",
              body: "The AES key is wrapped for the receiver's public key; servers never see it.",
            },
            {
              icon: Fingerprint,
              title: "SHA-256",
              body: "The receiver proves byte-identical delivery before the file is released.",
            },
            {
              icon: FileLock2,
              title: "Trust engine",
              body: "Token replay, tampering and session anomalies lower trust and block access.",
            },
          ].map((f) => (
            <div key={f.title} className="panel p-5">
              <f.icon className="size-5 text-primary" />
              <p className="mt-3 text-sm font-medium">{f.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-muted-foreground">{f.body}</p>
            </div>
          ))}
        </section>

        <section className="mt-12 grid gap-6 lg:grid-cols-2">
          <SecurityChecklist />
          <div className="panel flex flex-col justify-between p-6">
            <div>
              <h2 className="text-lg font-semibold">Security Demonstration Center</h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                A controlled security lab runs every demonstration through the production threat
                engine — integrity failures, token replay and session anomalies are detected, scored
                and audited exactly as in real transfers.
              </p>
            </div>
            <Button className="mt-6 w-fit" variant="outline" asChild>
              <Link to="/auth">Open the Security Lab</Link>
            </Button>
          </div>
        </section>
      </main>

      <footer className="border-t border-border py-6 text-center text-xs text-muted-foreground">
        SentinelCrypt — Web Crypto API only. No custom cryptographic primitives.
      </footer>
    </div>
  );
}
