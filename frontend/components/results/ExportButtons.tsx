"use client";

import { Copy, Download } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import type { ScanResponse } from "@/lib/types";
import { buildReportText } from "@/lib/utils";

export function ExportButtons({ result }: { result: ScanResponse }) {
  const onDownloadJson = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `${result.filename.replace(/\.sol$/i, "")}-report.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const onCopyReport = async () => {
    await navigator.clipboard.writeText(buildReportText(result));
    toast.success("Report copied to clipboard");
  };

  return (
    <div className="flex flex-col gap-3 sm:flex-row">
      <Button variant="outline" onClick={onDownloadJson}>
        <Download data-icon="inline-start" />
        Download JSON
      </Button>
      <Button variant="outline" onClick={onCopyReport}>
        <Copy data-icon="inline-start" />
        Copy Report
      </Button>
    </div>
  );
}
