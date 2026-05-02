"use client";

import { Controller, type Control } from "react-hook-form";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import type { RagProvider, ScanMode, ThresholdMode } from "@/lib/types";

type FormValues = {
  filename: string;
  sourceCode: string;
  includeRag: boolean;
  ragProvider: RagProvider;
  thresholdMode: ThresholdMode;
  scanMode: ScanMode;
};

const scanModeOptions: Array<{ value: ScanMode; label: string }> = [
  { value: "fast", label: "Fast" },
  { value: "deep", label: "Deep" },
];

const thresholdOptions: Array<{ value: ThresholdMode; label: string }> = [
  { value: "default", label: "Default" },
  { value: "tuned", label: "Tuned" },
  { value: "high_recall", label: "High Recall" },
];

export function ScanOptions({ control }: { control: Control<FormValues> }) {
  return (
    <div className="flex flex-1 flex-col gap-4 lg:flex-row lg:items-end">
      <Controller
        control={control}
        name="scanMode"
        render={({ field }) => (
          <Field label="Scan mode" className="lg:w-48">
            <Select value={field.value} onValueChange={field.onChange}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {scanModeOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}
      />

      <Controller
        control={control}
        name="thresholdMode"
        render={({ field }) => (
          <Field label="Threshold Mode" className="lg:w-48">
            <Select value={field.value} onValueChange={field.onChange}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {thresholdOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        )}
      />

      <Controller
        control={control}
        name="includeRag"
        render={({ field }) => (
          <div className="flex flex-1 items-center justify-between gap-4 lg:pb-1">
            <div className="min-w-0">
              <p className="text-sm font-medium text-foreground">Include RAG explanation</p>
              <p className="truncate text-xs text-muted-foreground">
                Append mitigation context and references when available.
              </p>
            </div>
            <Switch checked={field.value} onCheckedChange={field.onChange} />
          </div>
        )}
      />
    </div>
  );
}

function Field({
  children,
  className,
  label,
}: {
  children: React.ReactNode;
  className?: string;
  label: string;
}) {
  return (
    <label className={["flex flex-col gap-2", className ?? ""].filter(Boolean).join(" ")}>
      <span className="text-xs font-semibold uppercase tracking-[0.16em] text-[#767586]">
        {label}
      </span>
      {children}
    </label>
  );
}
