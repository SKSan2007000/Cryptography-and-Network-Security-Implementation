import { Radar } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { GEO_DISCLAIMER, type LabThreatIntel } from "@/lib/security-lab-intel";

function Line({ label, value, simulated }: { label: string; value: string; simulated?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1">
      <span className="text-xs text-muted-foreground">{label}</span>
      <span className="flex flex-wrap items-center justify-end gap-1.5 text-right">
        <span className="mono break-all text-[11px]">{value}</span>
        {simulated ? (
          <Badge variant="outline" className="border-warning/60 text-[9px] text-warning">
            SIMULATED
          </Badge>
        ) : null}
      </span>
    </div>
  );
}

export function ThreatIntelPanel({ intel }: { intel: LabThreatIntel }) {
  return (
    <Card className="panel">
      <CardHeader className="pb-2">
        <CardTitle className="flex items-center gap-2 text-sm">
          <Radar className="size-4 text-warning" /> Security Intelligence
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Line label="Threat source" value={intel.threatSource} />
        <Line label="Source IP" value={intel.sourceIp} simulated={intel.sourceIpSimulated} />
        <Line label="Device" value={intel.device} />
        <Line label="Session" value={intel.sessionLabel} />
        <Line label="Threat" value={intel.threat.replace(/_/g, " ")} />
        <Line label="Severity" value={intel.severity} />
        <Line label="Approximate region" value={intel.approximateRegion} simulated />
        <div className="mt-3">
          <div className="flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Risk score</span>
            <span className="mono font-semibold">{intel.riskScore}/100</span>
          </div>
          <Progress value={intel.riskScore} className="mt-1.5 h-2" />
        </div>
        <p className="mt-3 text-[11px] leading-relaxed text-muted-foreground">{GEO_DISCLAIMER}</p>
      </CardContent>
    </Card>
  );
}
