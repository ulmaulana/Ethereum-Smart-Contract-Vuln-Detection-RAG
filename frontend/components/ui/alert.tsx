import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const alertVariants = cva(
  "relative w-full rounded-3xl border px-4 py-4 text-sm backdrop-blur [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-current",
  {
    variants: {
      variant: {
        default: "border-border/70 bg-card/70 text-card-foreground",
        destructive: "border-red-500/30 bg-red-500/10 text-red-500",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

function Alert({
  className,
  variant,
  ...props
}: React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>) {
  return <div role="alert" className={cn(alertVariants({ variant }), className)} {...props} />;
}

function AlertTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return <h5 className={cn("mb-1 pl-7 font-semibold", className)} {...props} />;
}

function AlertDescription({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("pl-7 text-sm text-muted-foreground", className)} {...props} />;
}

export { Alert, AlertDescription, AlertTitle };
