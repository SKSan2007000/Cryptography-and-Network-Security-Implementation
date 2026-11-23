import { createFileRoute } from "@tanstack/react-router";
import { Gauge } from "lucide-react";

import { AppShell } from "@/components/layout/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { PerformanceChart } from "@/components/security/PerformanceChart";
import { StatCard } from "@/components/security/StatCard";
import { useAdminOverview } from "./admin.index";

export const Route = createFileRoute("/_authenticated/admin/performance")({
  head: () => ({
    meta: [
      { title: "Performance — SentinelCrypt Admin" },
      {
        name: "description",
        content: "Measured cryptographic and transfer timings across the platform.",
      },
    ],
  }),
  component: AdminPerformancePage,
});

function AdminPerformancePage() {
  const overview = useAdminOverview();

  if (overview.isLoading) {
    return (
      <AppShell title="Performance">
        <Skeleton className="h-64 w-full" />
      </AppShell>
    );
  }

  const avg = overview.data?.averages ?? {
    encryptionMs: 0,
    hashingMs: 0,
    transferMs: 0,
    verificationMs: 0,
  };
  const samples = (overview.data?.transfers ?? []).filter((t) => {
    const m = t.metrics as Record<string, number> | null;
    return m && (m["encryptionMs"] ?? 0) > 0;
  }).length;

  return (
    <AppShell
      title="Performance"
      description="Real measured timings — no simulated numbers. Averages cover transfers with recorded metrics."
    >
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Avg SHA-256 Hashing" value={`${avg.hashingMs} ms`} icon={Gauge} />
        <StatCard label="Avg AES-256-GCM Encrypt" value={`${avg.encryptionMs} ms`} icon={Gauge} />
        <StatCard label="Avg Upload" value={`${avg.transferMs} ms`} icon={Gauge} />
        <StatCard label="Avg Verification" value={`${avg.verificationMs} ms`} icon={Gauge} />
      </div>

      <Card className="panel">
        <CardHeader>
          <CardTitle className="text-sm">Pipeline Timing Breakdown</CardTitle>
          <CardDescription>{samples} transfers with recorded metrics.</CardDescription>
        </CardHeader>
        <CardContent>
          <PerformanceChart
            data={[
              { name: "hashing", ms: avg.hashingMs },
              { name: "encryption", ms: avg.encryptionMs },
              { name: "upload", ms: avg.transferMs },
              { name: "verification", ms: avg.verificationMs },
            ]}
          />
        </CardContent>
      </Card>
    </AppShell>
  );
}
