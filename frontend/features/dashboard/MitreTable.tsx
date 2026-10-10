import { MitreMapping } from "@/types/analysis";

export default function MitreTable({ mappings }: { mappings: MitreMapping[] }) {
  if (mappings.length === 0) {
    return <p className="text-sm text-soc-muted">No MITRE ATT&CK techniques were mapped for this email.</p>;
  }
  return (
    <div className="space-y-3">
      {mappings.map((m) => (
        <div key={m.techniqueId} className="rounded-md border border-soc-panelBorder p-3">
          <p className="font-mono text-xs text-severity-medium">{m.techniqueId}</p>
          <p className="text-sm font-medium">{m.techniqueName}</p>
          <p className="mt-1 text-xs text-soc-muted">{m.justification}</p>
        </div>
      ))}
    </div>
  );
}
