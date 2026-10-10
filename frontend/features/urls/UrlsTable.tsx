import { ExtractedUrl } from "@/types/analysis";
import SeverityBadge from "@/components/SeverityBadge";

export default function UrlsTable({ urls }: { urls: ExtractedUrl[] }) {
  if (urls.length === 0) return <p className="text-sm text-soc-muted">No URLs were found in this email.</p>;

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr className="border-b border-soc-panelBorder text-xs uppercase tracking-wide text-soc-muted">
            <th className="py-2 pr-4">URL</th>
            <th className="py-2 pr-4">Domain</th>
            <th className="py-2 pr-4">Risk</th>
            <th className="py-2">Reason</th>
          </tr>
        </thead>
        <tbody>
          {urls.map((u) => (
            <tr key={u.id} className="border-b border-soc-panelBorder/50 align-top">
              <td className="max-w-xs truncate py-2 pr-4 font-mono text-xs" title={u.url}>{u.url}</td>
              <td className="py-2 pr-4">{u.domain ?? "—"}</td>
              <td className="py-2 pr-4"><SeverityBadge severity={u.risk} /></td>
              <td className="py-2 text-soc-muted">{u.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
