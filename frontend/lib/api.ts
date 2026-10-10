import { AnalysisResponse } from "@/types/analysis";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export class ApiError extends Error {}

export async function analyzeRawEmail(rawEmail: string): Promise<AnalysisResponse> {
  const res = await fetch(`${API_BASE}/api/analyze/email`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ rawEmail }),
  });
  if (!res.ok) {
    const body = await safeJson(res);
    throw new ApiError(body?.error ?? `Analysis failed (${res.status})`);
  }
  return res.json();
}

export async function analyzeEmlFile(file: File): Promise<AnalysisResponse> {
  const formData = new FormData();
  formData.append("file", file);
  const res = await fetch(`${API_BASE}/api/analyze/eml`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const body = await safeJson(res);
    throw new ApiError(body?.error ?? `Analysis failed (${res.status})`);
  }
  return res.json();
}

async function safeJson(res: Response) {
  try {
    return await res.json();
  } catch {
    return null;
  }
}
