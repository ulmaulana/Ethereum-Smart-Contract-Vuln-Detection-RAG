import { SearchCode, ShieldEllipsis } from "lucide-react";

export function EmptyState() {
  return (
    <div className="panel flex min-h-[500px] flex-col items-center justify-center px-6 text-center">
      <div className="flex size-20 items-center justify-center rounded-full bg-primary/10 text-primary">
        <ShieldEllipsis className="size-10" />
      </div>
      <h3 className="mt-6 text-2xl font-semibold">Submit code to see results</h3>
      <p className="mt-3 max-w-sm leading-7 text-muted-foreground">
        The results panel will show classifier confidence, vulnerable functions, mitigation steps,
        and exportable scan reports.
      </p>
      <div className="mt-8 flex items-center gap-3 rounded-full border border-border/70 bg-background/60 px-4 py-2 text-sm text-muted-foreground">
        <SearchCode className="size-4" />
        Waiting for Solidity source input
      </div>
    </div>
  );
}
