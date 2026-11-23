import { createFileRoute, Link } from "@tanstack/react-router";
import { BookOpen } from "lucide-react";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { SecurityDemo } from "@/components/security/SecurityDemo";
import { TrustScoreCard } from "@/components/security/TrustScoreCard";
import { useAuth } from "@/hooks/useAuth";
import { useSecurityEvents } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/demo")({
  head: () => ({
    meta: [
      { title: "Security Lab — SentinelCrypt" },
      {
        name: "description",
        content:
          "Controlled demonstration mode: simulate attacks and watch the production threat engine respond.",
      },
    ],
  }),
  component: DemoPage,
});

function DemoPage() {
  const { profile, refreshProfile } = useAuth();
  const events = useSecurityEvents(50);

  return (
    <AppShell
      title="Security Lab"
      description="Demonstration mode — simulated threats run through the real detection engine and are flagged DEMO SIMULATION."
      actions={
        <Button variant="outline" asChild>
          <Link to="/cryptography">
            <BookOpen className="mr-2 size-4" /> Cryptography reference
          </Link>
        </Button>
      }
    >
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2">
          <SecurityDemo
            onComplete={() => {
              void events.refetch();
              void refreshProfile();
            }}
          />
        </div>
        <TrustScoreCard
          score={profile?.trust_score ?? 100}
          reasons={(events.data ?? []).map((e) => ({
            id: e.id,
            event_type: e.event_type,
            trust_delta: e.trust_delta,
            created_at: e.created_at,
            simulated: e.simulated,
          }))}
        />
      </div>
      <p className="text-xs text-muted-foreground">
        Tip: open a transfer you created and mark it as a demo transfer to run simulations scoped to
        that transfer's audit trail.
      </p>
    </AppShell>
  );
}
