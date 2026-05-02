"use client";

import {
  Bar,
  BarChart,
  Cell,
  CartesianGrid,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { VULN_CLASSES } from "@/lib/constants";
import type { ScanResponse } from "@/lib/types";

export function ConfidenceChart({ result }: { result: ScanResponse }) {
  const data = Object.entries(result.predictions).map(([key, prediction]) => ({
    name: VULN_CLASSES[key as keyof typeof VULN_CLASSES].label,
    confidence: Number((prediction.confidence * 100).toFixed(1)),
    threshold: Number((prediction.threshold * 100).toFixed(1)),
    status: prediction.status,
    fill:
      prediction.status === "detected"
        ? "hsl(var(--destructive))"
        : prediction.status === "suspected"
          ? "hsl(38 92% 50%)"
          : "hsl(var(--primary))",
  }));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Classifier confidence overview</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[360px] w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16 }}>
              <CartesianGrid strokeDasharray="3 3" horizontal={false} strokeOpacity={0.15} />
              <XAxis type="number" domain={[0, 100]} />
              <YAxis dataKey="name" type="category" width={160} />
              <Tooltip
                cursor={{ fill: "rgba(99, 102, 241, 0.08)" }}
                formatter={(value) => `${value ?? 0}%`}
              />
              <ReferenceLine x={50} stroke="rgba(148, 163, 184, 0.45)" strokeDasharray="6 6" />
              <Bar dataKey="confidence" fill="hsl(var(--primary))" radius={[0, 8, 8, 0]}>
                {data.map((entry) => (
                  <Cell key={entry.name} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}
