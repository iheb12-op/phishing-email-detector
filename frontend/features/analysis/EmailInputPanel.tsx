"use client";

import { useRef, useState } from "react";
import { Upload, ScanSearch } from "lucide-react";

interface Props {
  onAnalyzeText: (raw: string) => void;
  onAnalyzeFile: (file: File) => void;
  loading: boolean;
  error: string | null;
}

export default function EmailInputPanel({ onAnalyzeText, onAnalyzeFile, loading, error }: Props) {
  const [raw, setRaw] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  return (
    <div className="rounded-lg border border-soc-panelBorder bg-soc-panel p-5">
      <textarea
        className="h-48 w-full resize-y rounded-md border border-soc-panelBorder bg-soc-bg p-3 font-mono text-sm text-soc-text placeholder:text-soc-muted focus:outline-none focus:ring-1 focus:ring-severity-low"
        placeholder="Paste the full raw email (including headers) here…"
        value={raw}
        onChange={(e) => setRaw(e.target.value)}
      />

      {error && <p className="mt-2 text-sm text-severity-high">{error}</p>}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          onClick={() => raw.trim() && onAnalyzeText(raw)}
          disabled={loading || !raw.trim()}
          className="inline-flex items-center gap-2 rounded-md bg-severity-low px-4 py-2 text-sm font-medium text-white disabled:opacity-40"
        >
          <ScanSearch className="h-4 w-4" />
          {loading ? "Analyzing…" : "Analyze pasted email"}
        </button>

        <span className="text-soc-muted text-sm">or</span>

        <button
          onClick={() => fileInputRef.current?.click()}
          disabled={loading}
          className="inline-flex items-center gap-2 rounded-md border border-soc-panelBorder px-4 py-2 text-sm font-medium text-soc-text disabled:opacity-40"
        >
          <Upload className="h-4 w-4" />
          Upload .eml file
        </button>
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) onAnalyzeFile(file);
            e.target.value = "";
          }}
        />
      </div>
    </div>
  );
}
