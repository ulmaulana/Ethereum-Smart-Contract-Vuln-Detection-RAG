import { cn } from "@/lib/utils";

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      className={cn(
        "rounded-2xl bg-[length:200%_100%] bg-gradient-to-r from-muted via-muted/70 to-muted animate-shimmer",
        className,
      )}
      {...props}
    />
  );
}

export { Skeleton };
