import { NextResponse } from "next/server";

export const runtime = "edge";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export async function GET(
  _request: Request,
  context: { params: Promise<{ jobId: string }> },
) {
  const { jobId } = await context.params;

  try {
    const response = await fetch(`${API_URL}/api/v1/scan/jobs/${jobId}`, {
      method: "GET",
      cache: "no-store",
    });

    if (!response.ok) {
      const payload = (await response.json().catch(() => null)) as
        | { detail?: string; error?: string }
        | null;
      const message =
        payload?.detail || payload?.error || `Upstream scan failed with ${response.status}`;
      return NextResponse.json({ error: message }, { status: response.status });
    }

    const data = await response.json();
    return NextResponse.json(data);
  } catch (error) {
    const message =
      error instanceof Error
        ? `Backend unavailable: ${error.message}`
        : "Backend unavailable.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
}
