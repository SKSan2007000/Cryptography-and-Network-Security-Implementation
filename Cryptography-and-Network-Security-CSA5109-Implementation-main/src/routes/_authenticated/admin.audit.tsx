import { createFileRoute } from "@tanstack/react-router";

import { AppShell } from "@/components/layout/AppShell";
import { Card, CardContent } from "@/components/ui/card";
import { AuditLogTable } from "@/components/security/AuditLogTable";
import { useAuditLogs } from "@/lib/queries";

export const Route = createFileRoute("/_authenticated/admin/audit")({
  head: () => ({
    meta: [
      { title: "System Audit — SentinelCrypt Admin" },
      {
        name: "description",
        content: "Full immutable audit trail across all users and transfers.",
      },
    ],
  }),
  component: AdminAuditPage,
});

function AdminAuditPage() {
  const audit = useAuditLogs({ limit: 500 });

  return (
    <AppShell
      title="System Audit"
      description="The complete immutable audit trail — logins, key operations, transfers and threat responses."
    >
      <Card className="panel">
        <CardContent className="p-4">
          <AuditLogTable rows={audit.data ?? []} loading={audit.isLoading} />
        </CardContent>
      </Card>
    </AppShell>
  );
}
