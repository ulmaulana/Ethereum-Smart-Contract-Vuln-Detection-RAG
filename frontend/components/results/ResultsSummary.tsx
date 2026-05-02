import { Clock3, Cpu, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { ScanResponse } from "@/lib/types";
import { detectedCount, formatDuration, suspectedCount } from "@/lib/utils";

export function ResultsSummary({ result }: { result: ScanResponse }) {
  const totalDetected = detectedCount(result);
  const totalSuspected = suspectedCount(result);
  const hasRiskSignal = totalDetected > 0 || totalSuspected > 0;

  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between gap-4">
        <div>
          <Badge variant={hasRiskSignal ? "destructive" : "success"}>
            {hasRiskSignal ? "Risk signal present" : "No class exceeded threshold"}
          </Badge>
          <CardTitle className="mt-4 text-2xl">Scan summary for {result.filename}</CardTitle>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 md:grid-cols-4">
        <div className="rounded-[24px] border border-border/60 bg-background/70 p-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <ShieldAlert className="size-4" />
            Detected classes
          </div>
          <p className="mt-3 text-3xl font-semibold">{totalDetected}</p>
        </div>
        <div className="rounded-[24px] border border-border/60 bg-background/70 p-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <ShieldAlert className="size-4" />
            Suspected classes
          </div>
          <p className="mt-3 text-3xl font-semibold">{totalSuspected}</p>
        </div>
        <div className="rounded-[24px] border border-border/60 bg-background/70 p-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock3 className="size-4" />
            Scan duration
          </div>
          <p className="mt-3 text-3xl font-semibold">{formatDuration(result.scan_duration_ms)}</p>
        </div>
        <div className="rounded-[24px] border border-border/60 bg-background/70 p-4">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Cpu className="size-4" />
            Model / mode
          </div>
          <p className="mt-3 text-xl font-semibold">
            {result.metadata.model_version}
          </p>
          <p className="mt-1 text-sm text-muted-foreground">{result.metadata.scan_mode}</p>
        </div>
      </CardContent>
    </Card>
  );
}
