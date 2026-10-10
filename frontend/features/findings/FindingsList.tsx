"use client";

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { Finding, Severity } from "@/types/analysis";
import SeverityBadge from "@/components/SeverityBadge";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

export default function FindingsList({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  if (findings.length === 0) {
    return <p className="text-sm text-soc-muted">No findings were generated for this email.</p>;
  }

  const sorted = [...findings].sort((a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity));

  return (
    <div className="space-y-2">
      {sorted.map((f) => {
        const isOpen = expanded.has(f.id);
        return (
          <div key={f.id} className="rounded-md border border-soc-panelBorder">
            <button
              onClick={() => toggle(f.id)}
              className="flex w-full items-center justify-between gap-3 p-3 text-left"
            >
              <div className="flex items-center gap-3">
                {isOpen ? <ChevronDown className="h-4 w-4 text-soc-muted" /> : <ChevronRight className="h-4 w-4 text-soc-muted" />}
                <SeverityBadge severity={f.severity} />
                <span className="text-sm font-medium">{f.title}</span>
              </div>
              <span className="text-xs text-soc-muted">+{f.scoreImpact} pts</span>
            </button>
            {isOpen && (
              <div className="space-y-2 border-t border-soc-panelBorder p-4 text-sm">
                <p className="text-soc-text">{f.description}</p>
                <p className="text-soc-muted"><span className="font-semibold text-soc-text">Evidence: </span>{f.evidence}</p>
                <p className="text-soc-muted"><span className="font-semibold text-soc-text">Recommendation: </span>{f.recommendation}</p>
                <p className="text-xs text-soc-muted">
                  Category: {f.category}
                  {f.mitreTechniqueId && <> · MITRE: {f.mitreTechniqueId}</>}
                </p>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
