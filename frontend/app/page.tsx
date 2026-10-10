"use client";

import { useState } from "react";
import { ShieldCheck } from "lucide-react";
import EmailInputPanel from "@/features/analysis/EmailInputPanel";
import Dashboard from "@/features/dashboard/Dashboard";
import { analyzeRawEmail, analyzeEmlFile, ApiError } from "@/lib/api";
import { AnalysisResponse } from "@/types/analysis";

export default function HomePage() {
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runAnalysis = async (fn: () => Promise<AnalysisResponse>) => {
    setLoading(true);
    setError(null);
    try {
      setResult(await fn());
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Unable to reach the analysis backend. Is it running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="mx-auto max-w-4xl px-6 py-12">
      <div className="mb-8 flex items-center gap-3">
        <ShieldCheck className="h-8 w-8 text-severity-safe" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Phishing Email Detector</h1>
          <p className="text-sm text-soc-muted">Educational SOC-style phishing analysis platform</p>
        </div>
      </div>

      <EmailInputPanel
        loading={loading}
        error={error}
        onAnalyzeText={(raw) => runAnalysis(() => analyzeRawEmail(raw))}
        onAnalyzeFile={(file) => runAnalysis(() => analyzeEmlFile(file))}
      />

      {result && (
        <div className="mt-8">
          <Dashboard analysis={result} />
        </div>
      )}
    </main>
  );
}
