"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import {
  BarChart3,
  BookOpen,
  ChevronDown,
  Download,
  FileCode2,
  FileText,
  HelpCircle,
  History,
  Info,
  LayoutDashboard,
  LoaderCircle,
  Maximize2,
  Minimize2,
  Plus,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
} from "lucide-react";
import * as React from "react";
import { Controller, useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { RAGExplanation } from "@/components/results/RAGExplanation";
import {
  FileUploadDropzone,
  MAX_SOLIDITY_FILE_SIZE,
} from "@/components/scan/FileUploadDropzone";
import { ScanButton } from "@/components/scan/ScanButton";
import { ScanOptions } from "@/components/scan/ScanOptions";
import { SolidityEditor } from "@/components/scan/SolidityEditor";
import { LoadingSkeleton } from "@/components/shared/LoadingSkeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { SCAN_PROGRESS_PHASES, VULN_CLASSES } from "@/lib/constants";
import type {
  DemoContract,
  Explanation,
  Prediction,
  ScanJobResponse,
  ScanRequest,
  ScanResponse,
  VulnerabilityKey,
} from "@/lib/types";
import { getScanJob, startScanJob } from "@/lib/api";
import { useScanStore } from "@/lib/store";
import {
  buildReportText,
  cn,
  detectedCount,
  formatPercent,
  suspectedCount,
  vulnerabilityOrdering,
} from "@/lib/utils";

const sourceByteLength = (value: string) => new TextEncoder().encode(value).length;

const scanFormSchema = z.object({
  filename: z
    .string()
    .trim()
    .min(1, "Filename is required.")
    .max(160, "Filename is too long.")
    .regex(/^[^\\/]+\.sol$/i, "Use a .sol filename without path separators."),
  sourceCode: z
    .string()
    .trim()
    .min(1, "Solidity source is required.")
    .refine(
      (value) => sourceByteLength(value) <= MAX_SOLIDITY_FILE_SIZE,
      "Source code must be 5 MB or smaller.",
    ),
  includeRag: z.boolean(),
  ragProvider: z.enum(["minimax"]),
  thresholdMode: z.enum(["default", "tuned", "high_recall"]),
  scanMode: z.enum(["fast", "deep"]),
});

type ScanFormValues = z.infer<typeof scanFormSchema>;

type ScannerWorkspaceProps = {
  initialCode?: string;
  initialFilename?: string;
  autoScan?: boolean;
  demoContracts?: DemoContract[];
  demoMode?: boolean;
};

function classifyScanError(message: string) {
  const normalized = message.toLowerCase();

  if (normalized.includes("http 529") || normalized.includes("overloaded_error")) {
    return {
      title: "MiniMax sedang overload",
      hint: "Backend hidup, tetapi provider MiniMax sedang sibuk. Coba ulangi dalam 1-5 menit.",
    };
  }

  if (normalized.includes("deep scan belum tersedia")) {
    return {
      title: "Deep scan belum tersedia",
      hint: "Gunakan Fast Scan sampai runtime analyzer untuk deep mode benar-benar tersedia.",
    };
  }

  if (normalized.includes("minimax_api_key")) {
    return {
      title: "Konfigurasi MiniMax belum valid",
      hint: "Periksa MINIMAX_API_KEY di root .env atau .env.local.",
    };
  }

  if (normalized.includes("backend unavailable") || normalized.includes("fetch failed")) {
    return {
      title: "Backend scan gagal dijangkau",
      hint: "Pastikan backend API berjalan dan NEXT_PUBLIC_API_URL di root .env mengarah ke service yang benar.",
    };
  }

  return {
    title: "Scan gagal diproses",
    hint: "Periksa pesan error di atas, lalu coba ulangi scan.",
  };
}

function scanMetrics(result: ScanResponse | null) {
  if (!result) {
    return {
      high: 0,
      medium: 0,
      low: 0,
      score: null,
      hasRiskSignal: false,
    };
  }

  const high = detectedCount(result);
  const medium = suspectedCount(result);
  const total = Object.keys(result.predictions).length;
  const low = Math.max(total - high - medium, 0);
  const confidencePenalty = Object.values(result.predictions).reduce((sum, prediction) => {
    if (prediction.status === "detected") {
      return sum + prediction.confidence * 10;
    }
    if (prediction.status === "suspected") {
      return sum + prediction.confidence * 4;
    }
    return sum;
  }, 0);
  const score = Math.max(0, Math.round(100 - high * 18 - medium * 7 - confidencePenalty));

  return {
    high,
    medium,
    low,
    score,
    hasRiskSignal: high > 0 || medium > 0,
  };
}

function downloadJsonReport(result: ScanResponse) {
  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${result.filename.replace(/\.sol$/i, "")}-report.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function ScannerWorkspace({
  initialCode = "",
  initialFilename = "MyContract.sol",
  autoScan = false,
  demoContracts,
  demoMode = false,
}: ScannerWorkspaceProps) {
  const setCurrentScan = useScanStore((state) => state.setCurrentScan);
  const addHistory = useScanStore((state) => state.addHistory);
  const [result, setResult] = React.useState<ScanResponse | null>(null);
  const [selectedDemo, setSelectedDemo] = React.useState(demoContracts?.[0]?.slug ?? "");
  const [statusMessage, setStatusMessage] = React.useState<string | null>(null);
  const [scanError, setScanError] = React.useState<string | null>(null);
  const [scanJob, setScanJob] = React.useState<ScanJobResponse | null>(null);
  const [loadingContext, setLoadingContext] = React.useState<{
    includeRag: boolean;
    scanMode: "fast" | "deep";
  }>({
    includeRag: true,
    scanMode: "fast",
  });
  const [, startTransition] = React.useTransition();
  const deferredResult = React.useDeferredValue(result);
  const [analysisFullSize, setAnalysisFullSize] = React.useState(false);
  const autoScanRef = React.useRef(false);
  const completionHandledRef = React.useRef<string | null>(null);

  const form = useForm<ScanFormValues>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      filename: initialFilename,
      sourceCode: initialCode,
      includeRag: true,
      ragProvider: "minimax",
      thresholdMode: "tuned",
      scanMode: "fast",
    },
  });

  const mutation = useMutation({
    mutationFn: startScanJob,
    onSuccess: (job) => {
      completionHandledRef.current = null;
      setScanJob(job);
      startTransition(() => {
        setResult(null);
        setScanError(null);
        setStatusMessage(job.progress.message);
      });
    },
    onError: (error) => {
      const message =
        error instanceof Error ? error.message : "Unable to scan contract.";

      setScanJob(null);
      startTransition(() => {
        setResult(null);
        setScanError(message);
        setStatusMessage("Scan failed.");
      });

      toast.error(message);
    },
  });

  const onSubmit = React.useCallback(
    (values: ScanFormValues) => {
      const payload: ScanRequest = {
        filename: values.filename,
        source_code: values.sourceCode,
        options: {
          include_rag: values.includeRag,
          rag_provider: values.ragProvider,
          threshold_mode: values.thresholdMode,
          scan_mode: values.scanMode,
        },
      };

      completionHandledRef.current = null;
      setLoadingContext({
        includeRag: values.includeRag,
        scanMode: values.scanMode,
      });
      setScanJob(null);
      startTransition(() => {
        setResult(null);
        setScanError(null);
        setStatusMessage(`Scanning contract in ${values.scanMode} mode...`);
      });
      mutation.mutate(payload);
    },
    [mutation, startTransition],
  );

  const submitCurrentForm = React.useCallback(() => {
    void form.handleSubmit((values) => onSubmit(values), () => {
      toast.error("Periksa filename dan source code sebelum scan.");
    })();
  }, [form, onSubmit]);

  React.useEffect(() => {
    if (!scanJob) {
      return;
    }

    if (scanJob.status === "completed" && scanJob.result) {
      if (completionHandledRef.current === scanJob.job_id) {
        return;
      }

      completionHandledRef.current = scanJob.job_id;
      const response = scanJob.result;
      startTransition(() => {
        setCurrentScan(response);
        addHistory(
          {
            filename: response.filename,
            source_code: form.getValues("sourceCode"),
            options: {
              include_rag: form.getValues("includeRag"),
              rag_provider: form.getValues("ragProvider"),
              threshold_mode: form.getValues("thresholdMode"),
              scan_mode: form.getValues("scanMode"),
            },
          },
          response,
        );
        setResult(response);
        setScanError(null);
        setStatusMessage("Scan complete.");
      });

      toast.success("Scan completed");
      setScanJob(null);
      return;
    }

    if (scanJob.status === "failed") {
      if (completionHandledRef.current === scanJob.job_id) {
        return;
      }

      completionHandledRef.current = scanJob.job_id;
      const message = scanJob.error || "Unable to scan contract.";
      startTransition(() => {
        setResult(null);
        setScanError(message);
        setStatusMessage("Scan failed.");
      });

      toast.error(message);
      setScanJob(null);
      return;
    }

    const timeout = window.setTimeout(async () => {
      try {
        const nextJob = await getScanJob(scanJob.job_id);
        setScanJob(nextJob);
        setStatusMessage(nextJob.progress.message);
      } catch (error) {
        const message =
          error instanceof Error ? error.message : "Unable to retrieve scan progress.";
        setScanJob(null);
        startTransition(() => {
          setResult(null);
          setScanError(message);
          setStatusMessage("Scan failed.");
        });
        toast.error(message);
      }
    }, 850);

    return () => window.clearTimeout(timeout);
  }, [addHistory, form, scanJob, setCurrentScan, startTransition]);

  React.useEffect(() => {
    if (!autoScan || autoScanRef.current) {
      return;
    }

    autoScanRef.current = true;
    submitCurrentForm();
  }, [autoScan, submitCurrentForm]);

  const handleDemoChange = (slug: string) => {
    setSelectedDemo(slug);
    const selected = demoContracts?.find((item) => item.slug === slug);
    if (!selected) {
      return;
    }

    form.setValue("filename", selected.filename, { shouldValidate: true });
    form.setValue("sourceCode", selected.source, { shouldValidate: true });
    setResult(null);
    setScanError(null);
    setStatusMessage(`Loaded ${selected.label} demo contract.`);

    window.setTimeout(() => {
      submitCurrentForm();
    }, 100);
  };

  const activeProgress = scanJob?.progress;
  const isLoading = mutation.isPending || scanJob !== null;
  const currentStep = activeProgress?.step_index ?? 0;

  return (
    <section className="min-h-[100svh] bg-[#f7f9fb] text-[#191c1e] lg:h-[100svh] lg:overflow-hidden">
      <ScannerTopBar />
      <div className="flex min-h-[calc(100svh-4rem)] flex-col lg:h-[calc(100svh-4rem)] lg:overflow-hidden lg:flex-row">
        {!analysisFullSize ? <ScannerSidebar onRunAudit={submitCurrentForm} /> : null}
        <div className="flex min-w-0 flex-1 flex-col xl:flex-row">
          <div
            className={cn(
              "min-w-0 flex-1 border-r border-[#d9dce5] bg-white",
              analysisFullSize && "hidden",
            )}
          >
            <CodePane
              demoContracts={demoContracts}
              demoMode={demoMode}
              form={form}
              isLoading={isLoading}
              onDemoChange={handleDemoChange}
              onSubmit={onSubmit}
              selectedDemo={selectedDemo}
              statusMessage={statusMessage}
            />
          </div>
          <AnalysisPanel
            error={scanError}
            includeRag={activeProgress?.include_rag ?? loadingContext.includeRag}
            isFullSize={analysisFullSize}
            isLoading={isLoading}
            onToggleFullSize={() => setAnalysisFullSize((value) => !value)}
            progressMessage={activeProgress?.message}
            progressPercent={activeProgress?.progress_percent}
            result={deferredResult}
            scanMode={activeProgress?.scan_mode ?? loadingContext.scanMode}
            stepIndex={currentStep}
          />
        </div>
      </div>
    </section>
  );
}

function ScannerTopBar() {
  return (
    <header className="flex h-16 items-center border-b border-[#d9dce5] bg-white/80 px-5 shadow-sm backdrop-blur md:px-12">
      <h1 className="text-xl font-bold tracking-tight text-[#070a14]">Sentinel Audit</h1>
    </header>
  );
}

function ScannerSidebar({ onRunAudit }: { onRunAudit: () => void }) {
  const navItems = [
    { label: "Security Scans", icon: LayoutDashboard, active: true },
    { label: "History", icon: Shield },
    { label: "Reports", icon: FileText },
    { label: "Analytics", icon: BarChart3 },
  ];

  return (
    <aside className="hidden w-[280px] shrink-0 border-r border-[#d9dce5] bg-white/80 px-5 py-8 shadow-[10px_0_30px_rgba(15,23,42,0.025)] backdrop-blur-xl lg:flex lg:flex-col">
      <div className="mb-10 flex items-center gap-3">
        <div className="flex size-10 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-[0_10px_24px_rgba(70,72,212,0.25)]">
          <Shield className="size-5" />
        </div>
        <div>
          <p className="text-lg font-black tracking-[0.18em] text-primary">Sentinel AI</p>
          <p className="mt-1 text-[11px] uppercase tracking-[0.18em] text-[#767586]">
            Clinical Intelligence
          </p>
        </div>
      </div>

      <Button
        className="mb-10 w-full justify-center rounded-lg border border-primary/20 bg-primary/10 text-primary shadow-none hover:bg-primary/15"
        type="button"
        variant="outline"
        onClick={onRunAudit}
      >
        <Plus data-icon="inline-start" />
        Run New Audit
      </Button>

      <nav className="flex flex-1 flex-col gap-2">
        {navItems.map((item) => {
          const Icon = item.icon;

          return (
            <button
              className={cn(
                "flex items-center gap-3 rounded-lg px-4 py-3 text-left text-sm font-medium text-[#607089] transition",
                item.active
                  ? "bg-primary/5 text-primary"
                  : "hover:bg-[#f2f4f6] hover:text-[#191c1e]",
              )}
              key={item.label}
              type="button"
            >
              <Icon className="size-5" />
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="mt-8 flex flex-col gap-3 border-t border-[#d9dce5] pt-8 text-sm text-[#607089]">
        <a className="flex items-center gap-3 px-4 py-2 hover:text-[#191c1e]" href="/about">
          <BookOpen className="size-4" />
          Docs
        </a>
        <a className="flex items-center gap-3 px-4 py-2 hover:text-[#191c1e]" href="/about">
          <HelpCircle className="size-4" />
          Support
        </a>
      </div>
    </aside>
  );
}

function CodePane({
  demoContracts,
  demoMode,
  form,
  isLoading,
  onDemoChange,
  onSubmit,
  selectedDemo,
  statusMessage,
}: {
  demoContracts?: DemoContract[];
  demoMode: boolean;
  form: ReturnType<typeof useForm<ScanFormValues>>;
  isLoading: boolean;
  onDemoChange: (slug: string) => void;
  onSubmit: (values: ScanFormValues) => void;
  selectedDemo: string;
  statusMessage: string | null;
}) {
  const sourceCode = form.watch("sourceCode");

  return (
    <form
      className="flex h-full min-h-[calc(100svh-4rem)] flex-col lg:min-h-0"
      onSubmit={form.handleSubmit(onSubmit, () => {
        toast.error("Periksa filename dan source code sebelum scan.");
      })}
    >
      {demoMode ? (
        <div className="grid gap-4 border-b border-[#d9dce5] bg-white px-6 py-4 md:grid-cols-[1fr_300px]">
          <Alert className="border-primary/20 bg-primary/5">
            <Info className="size-4" />
            <AlertTitle>Historical demonstration only</AlertTitle>
            <AlertDescription>
              Demo ini memakai kontrak insiden publik untuk menguji workflow, bukan reproduksi
              canonical exploit environment.
            </AlertDescription>
          </Alert>
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-[#767586]">
              Demo contract
            </p>
            <Select value={selectedDemo} onValueChange={onDemoChange}>
              <SelectTrigger>
                <SelectValue placeholder="Select contract" />
              </SelectTrigger>
              <SelectContent>
                {demoContracts?.map((contract) => (
                  <SelectItem key={contract.slug} value={contract.slug}>
                    {contract.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      ) : null}

      <div className="flex shrink-0 items-center justify-between gap-4 border-b border-[#d9dce5] bg-[#f2f4f6] px-5 py-3">
        <div className="flex min-w-0 flex-1 items-center gap-3">
          <FileCode2 className="size-4 shrink-0 text-[#6f6d7d]" />
          <Input
            id="filename"
            aria-label="Filename"
            className="h-8 max-w-xs border-transparent bg-transparent px-2 text-sm font-semibold shadow-none focus-visible:border-primary/40 focus-visible:bg-white"
            placeholder="MyContract.sol"
            {...form.register("filename")}
          />
          <span className="h-4 w-px bg-[#c7c4d7]" />
          <span className="text-xs text-[#767586]">UTF-8</span>
        </div>
        <div className="flex items-center gap-2 text-[#6f6d7d]">
          <SlidersHorizontal className="size-4" />
          <History className="size-4" />
        </div>
      </div>

      <Controller
        control={form.control}
        name="sourceCode"
        render={({ field }) => (
          <div className="relative flex min-h-0 flex-1">
            <SolidityEditor value={field.value} onChange={(value) => field.onChange(value)} />
            {field.value.length === 0 ? (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-6">
                <div className="pointer-events-auto w-full max-w-xl">
                  <FileUploadDropzone
                    onLoaded={({ filename: nextFilename, sourceCode: nextSource }) => {
                      form.setValue("filename", nextFilename, { shouldValidate: true });
                      form.setValue("sourceCode", nextSource, { shouldValidate: true });
                    }}
                  />
                </div>
              </div>
            ) : null}
          </div>
        )}
      />

      <div className="shrink-0 border-t border-[#d9dce5] bg-white/95 p-4 backdrop-blur">
        {statusMessage ? (
          <div className="mb-4 flex items-center gap-3 rounded-full border border-[#d9dce5] bg-[#f7f9fb] px-4 py-2 text-sm text-[#606070]">
            {isLoading ? (
              <LoaderCircle className="size-4 animate-spin text-primary" />
            ) : (
              <ShieldAlert className="size-4 text-primary" />
            )}
            <span className="truncate">{statusMessage}</span>
          </div>
        ) : null}
        <div className="flex flex-col gap-4 xl:flex-row xl:items-end">
          <ScanOptions control={form.control} />
          <div className="xl:w-44 xl:shrink-0 xl:self-end">
            <ScanButton disabled={!sourceCode.trim()} loading={isLoading} />
          </div>
        </div>
      </div>
    </form>
  );
}

function AnalysisPanel({
  error,
  includeRag,
  isFullSize,
  isLoading,
  onToggleFullSize,
  progressMessage,
  progressPercent,
  result,
  scanMode,
  stepIndex,
}: {
  error: string | null;
  includeRag: boolean;
  isFullSize: boolean;
  isLoading: boolean;
  onToggleFullSize: () => void;
  progressMessage?: string;
  progressPercent?: number;
  result: ScanResponse | null;
  scanMode: "fast" | "deep";
  stepIndex: number;
}) {
  const metrics = scanMetrics(result);
  const orderedPredictions = result
    ? vulnerabilityOrdering(Object.entries(result.predictions) as never)
    : [];
  const notablePredictions = orderedPredictions.filter(([, prediction]) => prediction.status !== "clean");

  return (
    <aside
      className={cn(
        "flex w-full shrink-0 flex-col border-l border-[#d9dce5] bg-[#f7f9fb]",
        isFullSize ? "xl:w-full" : "xl:w-[460px] 2xl:w-[500px]",
      )}
    >
      <div className="shrink-0 border-b border-[#d9dce5] bg-white/50 p-6">
        <div className="flex items-center justify-between gap-4">
          <h2 className="text-2xl font-semibold tracking-tight">Scan Analysis</h2>
          <Button
            aria-label={isFullSize ? "Exit full size analysis" : "Open full size analysis"}
            className="size-10 rounded-xl border-[#d9dce5] bg-white/85 text-[#464554] shadow-none hover:bg-primary/5 hover:text-primary"
            size="icon"
            type="button"
            variant="outline"
            onClick={onToggleFullSize}
          >
            {isFullSize ? <Minimize2 /> : <Maximize2 />}
          </Button>
        </div>

        <div
          className={cn(
            "mt-8 rounded-2xl border border-white/80 bg-white/70 p-6 shadow-[0_10px_30px_rgba(15,23,42,0.04)] backdrop-blur",
            isFullSize && "mx-auto max-w-3xl",
          )}
        >
          <ScoreGauge score={metrics.score} risk={metrics.hasRiskSignal} />
        </div>

        <div className={cn("mt-6 grid grid-cols-3 gap-2", isFullSize && "mx-auto max-w-3xl")}>
          <MetricBox label="High" tone="high" value={metrics.high} />
          <MetricBox label="Medium" tone="medium" value={metrics.medium} />
          <MetricBox label="Low" tone="low" value={metrics.low} />
        </div>
      </div>

      <div className={cn("min-h-0 flex-1 overflow-auto p-5", isFullSize && "px-6 md:px-10")}>
        {isLoading ? (
          <div className="flex flex-col gap-5">
            <div className="rounded-2xl border border-primary/20 bg-primary/5 p-4 text-sm text-primary">
              <div className="mb-3 flex items-center gap-2 font-medium">
                <LoaderCircle className="size-4 animate-spin" />
                {progressMessage ?? "Preparing backend scan job..."}
              </div>
              <Progress value={progressPercent ?? 0} />
              <p className="mt-2 text-xs text-primary/70">
                {scanMode === "fast" ? "Fast Scan" : "Deep Scan"}
              </p>
            </div>
            <LoadingSkeleton
              currentStep={stepIndex}
              currentMessage={progressMessage}
              progressPercent={progressPercent}
              steps={SCAN_PROGRESS_PHASES}
              includeRag={includeRag}
            />
          </div>
        ) : null}

        {!isLoading && error ? <AnalysisError message={error} /> : null}

        {!isLoading && !error ? (
          <div className={cn("flex flex-col gap-4", isFullSize && "mx-auto max-w-5xl")}>
            <div>
              <p className="px-2 text-xs font-semibold uppercase tracking-[0.16em] text-[#6f6d7d]">
                Vulnerabilities
              </p>
              <div className="mt-3 flex flex-col gap-3">
                {result ? (
                  notablePredictions.length ? (
                    notablePredictions.map(([key, prediction]) => (
                      <FindingCard
                        explanation={result.explanations.find((item) => item.class === key)}
                        key={key}
                        prediction={prediction}
                        vulnerabilityKey={key}
                      />
                    ))
                  ) : (
                    <div className="rounded-2xl border border-emerald-500/20 bg-white p-5 text-sm text-[#464554] shadow-sm">
                      No vulnerability class exceeded the configured threshold.
                    </div>
                  )
                ) : (
                  <div className="rounded-2xl border border-[#d9dce5] bg-white p-5 text-sm text-[#464554] shadow-sm">
                    Run a scan to populate classifier findings and mitigation notes.
                  </div>
                )}
              </div>
            </div>

            <div className="border-t border-[#d9dce5] pt-5">
              <p className="px-2 text-xs font-semibold uppercase tracking-[0.16em] text-[#6f6d7d]">
                Gas Optimization Tips
              </p>
              <div className="mt-3 flex gap-3 rounded-xl border border-[#d9dce5] bg-[#f2f4f6] p-4 text-sm text-[#464554]">
                <ShieldAlert className="mt-0.5 size-5 shrink-0 text-primary" />
                <p>
                  Consider packing variables in structural definitions to save storage slots.
                </p>
              </div>
            </div>
          </div>
        ) : null}
      </div>

      <div className="shrink-0 border-t border-[#d9dce5] bg-white/80 p-5 backdrop-blur">
        <Button
          className="w-full rounded-lg bg-[#191c1e] text-white shadow-none hover:bg-[#2d3133]"
          disabled={!result}
          type="button"
          onClick={() => {
            if (!result) {
              return;
            }
            downloadJsonReport(result);
            void navigator.clipboard
              ?.writeText(buildReportText(result))
              .then(() => toast.success("Report JSON downloaded and text copied"))
              .catch(() => toast.success("Report JSON downloaded"));
          }}
        >
          <Download data-icon="inline-start" />
          Export Full Report
        </Button>
      </div>
    </aside>
  );
}

function ScoreGauge({ risk, score }: { risk: boolean; score: number | null }) {
  const dashOffset = score === null ? 126 : 126 - (Math.max(0, Math.min(score, 100)) / 100) * 126;
  const tone = score === null ? "text-[#d8dadc]" : risk ? "text-[#c81d25]" : "text-emerald-500";

  return (
    <div className="relative flex h-[132px] items-end justify-center">
      <svg aria-hidden className="absolute top-2 h-28 w-48" viewBox="0 0 120 70">
        <path
          className="text-[#e0e3e5]"
          d="M 15 60 A 45 45 0 0 1 105 60"
          fill="none"
          stroke="currentColor"
          strokeLinecap="round"
          strokeWidth="10"
        />
        <path
          className={tone}
          d="M 15 60 A 45 45 0 0 1 105 60"
          fill="none"
          stroke="currentColor"
          strokeDasharray="126"
          strokeDashoffset={dashOffset}
          strokeLinecap="round"
          strokeWidth="10"
        />
      </svg>
      <div className="relative z-10 mb-1 text-center">
        <p className="text-4xl font-black leading-none">{score ?? "--"}</p>
        <p className="mt-2 text-[11px] font-semibold uppercase tracking-[0.24em] text-[#6f6d7d]">
          Security Score
        </p>
      </div>
    </div>
  );
}

function MetricBox({
  label,
  tone,
  value,
}: {
  label: string;
  tone: "high" | "medium" | "low";
  value: number;
}) {
  const classes = {
    high: "border-red-200 bg-red-50 text-red-700",
    medium: "border-orange-200 bg-orange-50 text-orange-800",
    low: "border-indigo-200 bg-indigo-50 text-primary",
  };

  return (
    <div className={cn("rounded-lg border p-4 text-center", classes[tone])}>
      <p className="text-xl font-bold">{value}</p>
      <p className="mt-1 text-xs text-[#2d3133]">{label}</p>
    </div>
  );
}

function FindingCard({
  explanation,
  prediction,
  vulnerabilityKey,
}: {
  explanation?: Explanation;
  prediction: Prediction;
  vulnerabilityKey: VulnerabilityKey;
}) {
  const [open, setOpen] = React.useState(false);
  const config = VULN_CLASSES[vulnerabilityKey];
  const detected = prediction.status === "detected";
  const suspected = prediction.status === "suspected";
  const badgeVariant = detected ? "destructive" : suspected ? "outline" : "success";
  const statusLabel = detected ? "High" : suspected ? "Med" : "Low";

  return (
    <div className="w-full overflow-hidden rounded-xl border border-[#d9dce5] bg-white shadow-sm">
      <button
        className="flex w-full items-start justify-between gap-3 p-4 text-left"
        type="button"
        onClick={() => setOpen((value) => !value)}
      >
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge className="tracking-[0.12em]" variant={badgeVariant}>
              {statusLabel}
            </Badge>
            <span className="text-xs font-medium text-[#6f6d7d]">{config.swc_id}</span>
            <span className="text-xs text-[#6f6d7d]">{formatPercent(prediction.confidence)}</span>
          </div>
          <h3 className="text-sm font-semibold text-[#191c1e]">{config.label}</h3>
          {prediction.vulnerable_functions.length ? (
            <p className="mt-2 truncate text-xs text-[#6f6d7d]">
              {prediction.vulnerable_functions.join(", ")}
            </p>
          ) : null}
        </div>
        <ChevronDown
          className={cn("mt-1 size-4 shrink-0 text-[#6f6d7d] transition", open && "rotate-180")}
        />
      </button>
      {open ? (
        <div className="border-t border-[#e0e3e5] px-4 pb-4 pt-3">
          <div className="mb-3">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[#6f6d7d]">
              Decision basis
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {prediction.decision_basis.length ? (
                prediction.decision_basis.map((signal) => (
                  <Badge key={signal} variant="outline">
                    {signal}
                  </Badge>
                ))
              ) : (
                <span className="text-sm text-[#6f6d7d]">No additional signal extracted.</span>
              )}
            </div>
          </div>
          {explanation ? <RAGExplanation explanation={explanation} /> : null}
        </div>
      ) : null}
    </div>
  );
}

function AnalysisError({ message }: { message: string }) {
  const details = classifyScanError(message);

  return (
    <Alert variant="destructive">
      <Info className="size-4" />
      <AlertTitle>{details.title}</AlertTitle>
      <AlertDescription>
        {message}
        <br />
        {details.hint}
      </AlertDescription>
    </Alert>
  );
}
