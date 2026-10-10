import { AnalysisResponse } from "@/types/analysis";
import Card from "@/components/Card";
import VerdictBanner from "@/components/VerdictBanner";
import FindingsList from "@/features/findings/FindingsList";
import UrlsTable from "@/features/urls/UrlsTable";
import AttachmentsTable from "@/features/urls/AttachmentsTable";
import MitreTable from "./MitreTable";
import RiskScoreChart from "./RiskScoreChart";
import { CheckCircle2, XCircle, HelpCircle } from "lucide-react";
import { AuthStatus } from "@/types/analysis";

function AuthPill({ label, status }: { label: string; status: AuthStatus }) {
  const Icon = status === "PASS" ? CheckCircle2 : status === "FAIL" ? XCircle : HelpCircle;
  const color = status === "PASS" ? "text-severity-safe" : status === "FAIL" ? "text-severity-critical" : "text-soc-muted";
  return (
    <div className="flex items-center gap-2 rounded-md border border-soc-panelBorder px-3 py-2">
      <Icon className={`h-4 w-4 ${color}`} />
      <span className="text-sm">{label}: <span className={`font-semibold ${color}`}>{status}</span></span>
    </div>
  );
}

export default function Dashboard({ analysis }: { analysis: AnalysisResponse }) {
  const o = analysis.emailOverview;
  return (
    <div className="space-y-6">
      <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex-1">
          <VerdictBanner verdict={analysis.verdict} score={analysis.riskScore} />
        </div>
        <RiskScoreChart score={analysis.riskScore} />
      </div>

      <Card title="Email Overview">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
          <div><dt className="text-soc-muted">Sender</dt><dd>{o.fromDisplayName ? `${o.fromDisplayName} <${o.fromAddress}>` : (o.fromAddress ?? "—")}</dd></div>
          <div><dt className="text-soc-muted">Recipient</dt><dd>{o.toAddress ?? "—"}</dd></div>
          <div><dt className="text-soc-muted">Subject</dt><dd>{o.subject ?? "—"}</dd></div>
          <div><dt className="text-soc-muted">Date</dt><dd>{o.date ?? "—"}</dd></div>
          <div><dt className="text-soc-muted">Reply-To</dt><dd>{o.replyToAddress ?? "—"}</dd></div>
          <div><dt className="text-soc-muted">Message-ID</dt><dd className="truncate">{o.messageId ?? "—"}</dd></div>
        </dl>
      </Card>

      <Card title="Authentication">
        <div className="flex flex-wrap gap-3">
          <AuthPill label="SPF" status={analysis.authentication.spf} />
          <AuthPill label="DKIM" status={analysis.authentication.dkim} />
          <AuthPill label="DMARC" status={analysis.authentication.dmarc} />
        </div>
      </Card>

      <Card title={`Threat Findings (${analysis.findings.length})`}>
        <FindingsList findings={analysis.findings} />
      </Card>

      <Card title={`Extracted URLs (${analysis.urls.length})`}>
        <UrlsTable urls={analysis.urls} />
      </Card>

      <Card title={`Attachments (${analysis.attachments.length})`}>
        <AttachmentsTable attachments={analysis.attachments} />
      </Card>

      <Card title="MITRE ATT&CK Mapping">
        <MitreTable mappings={analysis.mitreMappings} />
      </Card>

      <Card title="Recommended Actions">
        <ul className="list-inside list-disc space-y-1 text-sm">
          {analysis.recommendedActions.map((a, i) => <li key={i}>{a}</li>)}
        </ul>
      </Card>
    </div>
  );
}
