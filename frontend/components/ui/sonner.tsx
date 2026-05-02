"use client";

import { Toaster as Sonner, type ToasterProps } from "sonner";

import { useTheme } from "@/components/providers/ThemeProvider";

function Toaster(props: ToasterProps) {
  const { resolvedTheme } = useTheme();

  return (
    <Sonner
      theme={resolvedTheme as ToasterProps["theme"]}
      position="top-right"
      richColors
      toastOptions={{
        classNames: {
          toast: "border border-border/60 bg-background text-foreground shadow-xl",
          description: "text-muted-foreground",
        },
      }}
      {...props}
    />
  );
}

export { Toaster };
