import { createFileRoute } from "@tanstack/react-router";
import { format } from "date-fns";
import { Loader2, Save } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { EncryptionKeySetup } from "@/components/security/EncryptionKeySetup";
import { TrustScoreCard } from "@/components/security/TrustScoreCard";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { getKeyRecord, type KeyRecord } from "@/lib/keyvault";
import { useSecurityEvents } from "@/lib/queries";
import { riskBand } from "@/lib/security-rules";

export const Route = createFileRoute("/_authenticated/profile")({
  head: () => ({
    meta: [
      { title: "Profile — SentinelCrypt" },
      { name: "description", content: "Manage your identity, trust score and RSA key pair." },
    ],
  }),
  component: ProfilePage,
});

function ProfilePage() {
  const { user, profile, refreshProfile } = useAuth();
  const events = useSecurityEvents(50);
  const [fullName, setFullName] = useState("");
  const [organization, setOrganization] = useState("");
  const [saving, setSaving] = useState(false);
  const [keys, setKeys] = useState<KeyRecord | null>(null);

  useEffect(() => {
    setFullName(profile?.full_name ?? "");
    setOrganization(profile?.organization ?? "");
  }, [profile]);

  useEffect(() => {
    if (!user) return;
    void getKeyRecord(user.id).then(setKeys);
  }, [user]);

  async function save() {
    if (!user) return;
    setSaving(true);
    const { error } = await supabase
      .from("profiles")
      .update({ full_name: fullName.trim() || null, organization: organization.trim() || null })
      .eq("id", user.id);
    setSaving(false);
    if (error) {
      toast.error(error.message);
    } else {
      toast.success("Profile updated.");
      void refreshProfile();
    }
  }

  const score = profile?.trust_score ?? 100;

  return (
    <AppShell title="Profile" description="Your identity, trust score and cryptographic keys.">
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="panel lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-sm">Account</CardTitle>
            <CardDescription>{profile?.email}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="fullName">Full name</Label>
                <Input
                  id="fullName"
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="org">Organization</Label>
                <Input
                  id="org"
                  value={organization}
                  onChange={(e) => setOrganization(e.target.value)}
                />
              </div>
            </div>
            <div className="flex items-center gap-4">
              <Button onClick={() => void save()} disabled={saving}>
                {saving ? (
                  <Loader2 className="mr-2 size-4 animate-spin" />
                ) : (
                  <Save className="mr-2 size-4" />
                )}
                Save changes
              </Button>
              <p className="mono text-xs text-muted-foreground">
                member since {profile ? format(new Date(profile.created_at), "dd MMM yyyy") : "—"} ·{" "}
                {riskBand(score).toLowerCase()}
              </p>
            </div>
          </CardContent>
        </Card>

        <TrustScoreCard
          score={score}
          reasons={(events.data ?? []).map((e) => ({
            id: e.id,
            event_type: e.event_type,
            trust_delta: e.trust_delta,
            created_at: e.created_at,
            simulated: e.simulated,
          }))}
        />
      </div>

      {user ? (
        <EncryptionKeySetup userId={user.id} keyRecord={keys} onProvisioned={setKeys} />
      ) : null}

      {keys ? (
        <p className="mono text-xs text-muted-foreground">
          {keys.algorithm} · published {format(new Date(keys.created_at), "dd MMM yyyy HH:mm")}
        </p>
      ) : null}
    </AppShell>
  );
}
