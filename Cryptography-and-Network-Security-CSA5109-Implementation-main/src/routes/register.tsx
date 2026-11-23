import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { Check, Loader2, ShieldCheck, X } from "lucide-react";
import { useMemo, useState } from "react";
import { toast } from "sonner";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { supabase } from "@/integrations/supabase/client";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/register")({
  head: () => ({
    meta: [
      { title: "Create account — SentinelCrypt" },
      {
        name: "description",
        content:
          "Create a SentinelCrypt account to exchange files protected with AES-256-GCM, RSA-OAEP key wrapping and SHA-256 integrity verification.",
      },
      { property: "og:title", content: "Create account — SentinelCrypt" },
      {
        property: "og:description",
        content:
          "Register for trust-aware secure file transfer with full audit and threat detection.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: RegisterPage,
});

export const PASSWORD_RULES = [
  { id: "length", label: "At least 10 characters", test: (v: string) => v.length >= 10 },
  { id: "upper", label: "An uppercase letter", test: (v: string) => /[A-Z]/.test(v) },
  { id: "lower", label: "A lowercase letter", test: (v: string) => /[a-z]/.test(v) },
  { id: "number", label: "A number", test: (v: string) => /[0-9]/.test(v) },
  { id: "special", label: "A special character", test: (v: string) => /[^A-Za-z0-9]/.test(v) },
];

export function passwordStrength(value: string): { score: number; label: string } {
  const passed = PASSWORD_RULES.filter((r) => r.test(value)).length;
  const score = (passed / PASSWORD_RULES.length) * 100;
  const label = score === 100 ? "Strong" : score >= 60 ? "Moderate" : score > 0 ? "Weak" : "—";
  return { score, label };
}

function RegisterPage() {
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const strength = useMemo(() => passwordStrength(password), [password]);
  const allRulesPass = PASSWORD_RULES.every((r) => r.test(password));

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    if (fullName.trim().length < 2) return setError("Enter your full name.");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setError("Enter a valid email address.");
    if (!allRulesPass) return setError("The password does not meet all requirements.");
    if (password !== confirm) return setError("Passwords do not match.");

    setBusy(true);
    try {
      const { data, error: signUpError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          emailRedirectTo: `${window.location.origin}/auth`,
          data: { full_name: fullName.trim() },
        },
      });
      if (signUpError) {
        setError(signUpError.message);
        return;
      }
      if (data.session) {
        toast.success("Account created.");
        void navigate({ to: "/dashboard", replace: true });
        return;
      }
      setDone(true);
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <Card className="panel w-full max-w-md text-center">
          <CardHeader>
            <CardTitle>Verify your email</CardTitle>
            <CardDescription>
              We sent a verification link to {email}. Confirm your address, then sign in to reach
              your dashboard.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button asChild className="w-full">
              <Link to="/auth">Go to sign in</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-12">
      <Card className="panel w-full max-w-md">
        <CardHeader className="space-y-1">
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-primary" />
            <span className="text-sm font-semibold">SentinelCrypt</span>
          </div>
          <CardTitle className="text-2xl">Create account</CardTitle>
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
              <Label htmlFor="name">Full Name</Label>
              <Input
                id="name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
              <Progress value={strength.score} className="h-1.5" />
              <p className="text-xs text-muted-foreground">Strength: {strength.label}</p>
              <ul className="grid gap-1 pt-1">
                {PASSWORD_RULES.map((rule) => {
                  const ok = rule.test(password);
                  return (
                    <li
                      key={rule.id}
                      className={cn(
                        "flex items-center gap-1.5 text-xs",
                        ok ? "text-secure" : "text-muted-foreground",
                      )}
                    >
                      {ok ? <Check className="size-3.5" /> : <X className="size-3.5" />}
                      {rule.label}
                    </li>
                  );
                })}
              </ul>
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirm">Confirm Password</Label>
              <Input
                id="confirm"
                type="password"
                autoComplete="new-password"
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                required
              />
            </div>

            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? <Loader2 className="mr-2 size-4 animate-spin" /> : null}
              Create Account
            </Button>
            <p className="text-center text-sm text-muted-foreground">
              Already registered?{" "}
              <Link to="/auth" className="text-primary hover:underline">
                Sign in
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
