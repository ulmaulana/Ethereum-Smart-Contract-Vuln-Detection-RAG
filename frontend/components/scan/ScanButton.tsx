"use client";

import { LoaderCircle, Radar } from "lucide-react";

import { Button } from "@/components/ui/button";

export function ScanButton({
  disabled,
  loading,
}: {
  disabled: boolean;
  loading: boolean;
}) {
  return (
    <Button className="w-full justify-center" size="lg" disabled={disabled || loading} type="submit">
      {loading ? <LoaderCircle className="animate-spin" data-icon="inline-start" /> : <Radar data-icon="inline-start" />}
      {loading ? "Scanning..." : "Scan Now"}
    </Button>
  );
}
