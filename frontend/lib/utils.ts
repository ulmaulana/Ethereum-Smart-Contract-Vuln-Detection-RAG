import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { ScanResponse, VulnerabilityKey } from "@/lib/types";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatPercent(value: number) {
  return `${Math.round(value * 100)}%`;
}

export function formatDuration(value: number) {
  if (value < 1000) {
    return `${value} ms`;
  }

  return `${(value / 1000).toFixed(2)} s`;
}

export function titleFromKey(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function detectedCount(result: ScanResponse) {
  return Object.values(result.predictions).filter((item) => item.detected).length;
}

export function suspectedCount(result: ScanResponse) {
  return Object.values(result.predictions).filter((item) => item.status === "suspected").length;
}

export function buildReportText(result: ScanResponse) {
  const notable = Object.entries(result.predictions)
    .filter(([, prediction]) => prediction.status !== "clean")
    .map(([key, prediction]) => {
      const functions = prediction.vulnerable_functions.length
        ? prediction.vulnerable_functions.join(", ")
        : "no function extracted";

      return `- ${titleFromKey(key)}: ${prediction.status} | ${formatPercent(prediction.confidence)} confidence | ${functions}`;
    })
    .join("\n");

  return [
    `Smart Contract Vulnerability Detector`,
    `File: ${result.filename}`,
    `Status: ${result.status}`,
    `Scan duration: ${formatDuration(result.scan_duration_ms)}`,
    `Model version: ${result.metadata.model_version}`,
    `Scan mode: ${result.metadata.scan_mode}`,
    "",
    notable ? "Detected or suspected classes:" : "No classes exceeded the configured threshold.",
    notable || "",
  ]
    .filter(Boolean)
    .join("\n");
}

export function vulnerabilityOrdering(
  entries: Array<[VulnerabilityKey, ScanResponse["predictions"][VulnerabilityKey]]>,
) {
  const statusRank = {
    detected: 2,
    suspected: 1,
    clean: 0,
  } as const;

  return entries.toSorted(([, left], [, right]) => {
    const statusDelta = statusRank[right.status] - statusRank[left.status];
    if (statusDelta !== 0) {
      return statusDelta;
    }
    return right.confidence - left.confidence;
  });
}
