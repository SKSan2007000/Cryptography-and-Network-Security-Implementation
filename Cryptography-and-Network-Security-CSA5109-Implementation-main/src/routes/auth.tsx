import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Eye, EyeOff, Loader2, Lock, LockKeyhole, Mail, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { recordLoginAttempt } from "@/lib/sentinel.functions";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — SentinelCrypt Secure Transfer" },
      {
        name: "description",
        content:
          "Sign in to SentinelCrypt to send and receive AES-256-GCM encrypted files with SHA-256 integrity verification.",
      },
      { property: "og:title", content: "Sign in — SentinelCrypt Secure Transfer" },
      {
        property: "og:description",
        content: "Trust every transfer. Verify every byte. Authenticated secure file exchange.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const { user, loading } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!loading && user) void navigate({ to: "/dashboard", replace: true });
  }, [user, loading, navigate]);

  const validate = () => {
    if (!/^\S+@\S+\.\S+$/.test(email)) return "Enter a valid email address.";
    if (password.length < 8) return "Password must be at least 8 characters.";
    return null;
  };

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const invalid = validate();
    if (invalid) {
      setError(invalid);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const limit = await recordLoginAttempt({ data: { email, success: false } }).catch(() => null);
      if (limit?.locked) {
        setError("Too many sign-in attempts. Please wait before trying again.");
        return;
      }
      const { error: authError } = await supabase.auth.signInWithPassword({ email, password });
      if (authError) {
        // Deliberately generic: never reveals whether an account exists.
        setError("Invalid email or password.");
        return;
      }
      await recordLoginAttempt({ data: { email, success: true } }).catch(() => null);
      toast.success("Signed in. Establishing monitored session…");
      void navigate({ to: "/dashboard", replace: true });
    } catch {
      setError("Sign-in is temporarily unavailable. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  async function handleReset() {
    if (!/^\S+@\S+\.\S+$/.test(email)) {
      setError("Enter your email address first, then choose Forgot password.");
      return;
    }
    await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/auth`,
    });
    toast.success("If an account exists for that address, a reset link has been sent.");
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-2">
      <section className="hidden flex-col justify-between border-r border-border bg-sidebar p-10 lg:flex">
        <div className="flex items-center gap-2.5">
          <span className="rounded-md bg-primary/15 p-2 text-primary">
            <ShieldCheck className="size-5" />
          </span>
          <span className="text-sm font-semibold tracking-tight">SentinelCrypt</span>
        </div>
        <div className="space-y-4">
          <h2 className="text-3xl font-semibold tracking-tight">
            Trust Every Transfer.
            <br />
            Verify Every Byte.
          </h2>
          <p className="max-w-md text-sm text-muted-foreground">
            Files are encrypted in your browser with AES-256-GCM, the session key is wrapped with
            the recipient's RSA-OAEP 2048 public key, and every byte is verified with SHA-256 before
            it is released.
          </p>
          <ul className="space-y-2 text-sm text-muted-foreground">
            {[
              "Client-side AES-256-GCM encryption",
              "RSA-OAEP 2048 / SHA-256 key wrapping",
              "SHA-256 end-to-end integrity proof",
              "Trust-aware threat detection and audit trail",
            ].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <ShieldCheck className="size-4 text-secure" /> {item}
              </li>
            ))}
          </ul>
        </div>
        <p className="mono text-[11px] text-muted-foreground">
          Web Crypto API · No custom cryptographic primitives
        </p>
      </section>

      <section className="flex items-center justify-center px-4 py-12">
        <Card className="panel w-full max-w-md">
          <CardHeader className="space-y-1">
            <div className="flex items-center gap-2 lg:hidden">
              <ShieldCheck className="size-5 text-primary" />
              <span className="text-sm font-semibold">SentinelCrypt</span>
            </div>
            <CardTitle className="text-2xl">Sign in</CardTitle>
            <CardDescription>Trust Every Transfer. Verify Every Byte.</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              {error ? (
                <Alert className="border-critical/40 bg-critical/5">
                  <AlertDescription className="text-sm">{error}</AlertDescription>
                </Alert>
              ) : null}

              <div className="space-y-2">
                <Label htmlFor="email">Email</Label>
                <div className="relative">
                  <Mail className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                  <Input
                    id="email"
                    type="email"
                    autoComplete="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="pl-8"
                    placeholder="you@organisation.com"
                    required
                  />
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <div className="relative">
                  <Lock className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
                  <Input
                    id="password"
                    type={show ? "text" : "password"}
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="px-8"
                    required
                  />
                  <button
                    type="button"
                    onClick={() => setShow((v) => !v)}
                    className="absolute right-2 top-2.5 text-muted-foreground"
                    aria-label={show ? "Hide password" : "Show password"}
                  >
                    {show ? <EyeOff className="size-4" /> : <Eye className="size-4" />}
                  </button>
                </div>
              </div>

              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
                Sign In
              </Button>

              <div className="flex items-center justify-between text-sm">
                <button
                  type="button"
                  onClick={handleReset}
                  className="text-primary hover:underline"
                >
                  Forgot password
                </button>
                <Link to="/register" className="text-primary hover:underline">
                  Create account
                </Link>
              </div>

              <p className="flex items-center justify-center gap-1.5 rounded-md border border-secure/30 bg-secure/5 py-2 text-xs text-secure">
                <LockKeyhole className="size-3.5" /> Secure TLS Connection
              </p>
            </form>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
