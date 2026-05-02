import type { ScanJobResponse, ScanRequest } from "@/lib/types";

export async function startScanJob(input: ScanRequest): Promise<ScanJobResponse> {
  const response = await fetch("/api/scan", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(input),
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as
      | { error?: string }
      | null;
    throw new Error(payload?.error || `Scan failed with status ${response.status}`);
  }

  return (await response.json()) as ScanJobResponse;
}

export async function getScanJob(jobId: string): Promise<ScanJobResponse> {
  const response = await fetch(`/api/scan/${jobId}`, {
    cache: "no-store",
  });

  if (!response.ok) {
    const payload = (await response.json().catch(() => null)) as
      | { error?: string }
      | null;
    throw new Error(payload?.error || `Scan polling failed with status ${response.status}`);
  }

  return (await response.json()) as ScanJobResponse;
}

export async function getHealthStatus() {
  const response = await fetch("/api/v1/health");
  return response.json();
}
