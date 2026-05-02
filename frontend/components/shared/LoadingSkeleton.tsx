import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";

type LoadingSkeletonProps = {
  compact?: boolean;
  currentStep?: number;
  currentMessage?: string;
  progressPercent?: number;
  steps?: readonly {
    id: string;
    title: string;
    description: string;
    duration: string;
  }[];
  includeRag?: boolean;
};

export function LoadingSkeleton({
  compact = false,
  currentStep = 0,
  currentMessage,
  progressPercent,
  steps = [],
  includeRag = true,
}: LoadingSkeletonProps) {
  const activeSteps = includeRag ? steps : steps.filter((step) => step.id !== "rag");
  const safeIndex = activeSteps.length === 0 ? 0 : Math.min(currentStep, activeSteps.length - 1);
  const calculatedProgressPercent =
    progressPercent ??
    activeSteps.length <= 1 ? 100 : Math.round(((safeIndex + 1) / activeSteps.length) * 100);

  return (
    <div className="space-y-5">
      <div className="rounded-[28px] border border-border/70 bg-background/70 p-5">
        <div className="mb-4 flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-foreground">
              {activeSteps[safeIndex]?.title ?? "Preparing scan"}
            </p>
            <p className="mt-1 text-sm text-muted-foreground">
              {currentMessage ??
                activeSteps[safeIndex]?.description ??
                "Menyiapkan pipeline inferensi dan menyusun hasil scan."}
            </p>
          </div>
          <div className="rounded-full border border-primary/20 bg-primary/10 px-3 py-1 text-xs font-medium text-primary">
            {calculatedProgressPercent}% complete
          </div>
        </div>

        <Progress value={calculatedProgressPercent} />

        <div className="mt-5 grid gap-3">
          {activeSteps.map((step, index) => {
            const state =
              index < safeIndex ? "done" : index === safeIndex ? "active" : "pending";

            return (
              <div
                key={step.id}
                className={[
                  "rounded-2xl border px-4 py-3 transition-colors",
                  state === "active"
                    ? "border-primary/30 bg-primary/10"
                    : state === "done"
                      ? "border-emerald-500/20 bg-emerald-500/5"
                      : "border-border/60 bg-card/50",
                ].join(" ")}
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div
                      className={[
                        "flex size-7 items-center justify-center rounded-full text-xs font-semibold",
                        state === "active"
                          ? "bg-primary text-primary-foreground"
                          : state === "done"
                            ? "bg-emerald-500 text-white"
                            : "bg-muted text-muted-foreground",
                      ].join(" ")}
                    >
                      {state === "done" ? "OK" : index + 1}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-foreground">{step.title}</p>
                      <p className="text-xs text-muted-foreground">{step.description}</p>
                    </div>
                  </div>
                  <div className="text-right text-xs text-muted-foreground">
                    <p>{step.duration}</p>
                    <p>
                      {state === "active"
                        ? "Sedang diproses"
                        : state === "done"
                          ? "Selesai"
                          : "Menunggu"}
                    </p>
                  </div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="mt-4 rounded-2xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 text-sm text-muted-foreground">
          {includeRag
            ? "Fase yang paling lama biasanya RAG explanation, karena backend melakukan retrieval lalu memanggil MiniMax untuk menghasilkan penjelasan dan mitigasi."
            : "RAG dimatikan, jadi scan hanya menjalankan parser, feature extraction, dan classifier tanpa memanggil model LLM."}
        </div>
      </div>

      <div className="flex flex-col gap-4">
        <Skeleton className={compact ? "h-16 w-full" : "h-20 w-full"} />
        <Skeleton className={compact ? "h-24 w-full" : "h-32 w-full"} />
        <Skeleton className={compact ? "h-32 w-full" : "h-40 w-full"} />
      </div>
    </div>
  );
}
