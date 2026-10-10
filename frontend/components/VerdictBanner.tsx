import clsx from "clsx";
import { ShieldAlert, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import { Verdict } from "@/types/analysis";

const CONFIG: Record<Verdict, { label: string; color: string; Icon: typeof ShieldCheck }> = {
  SAFE: { label: "SAFE", color: "text-severity-safe border-severity-safe/40 bg-severity-safe/10", Icon: ShieldCheck },
  SUSPICIOUS: { label: "SUSPICIOUS", color: "text-severity-medium border-severity-medium/40 bg-severity-medium/10", Icon: ShieldQuestion },
  LIKELY_PHISHING: { label: "LIKELY PHISHING", color: "text-severity-high border-severity-high/40 bg-severity-high/10", Icon: ShieldAlert },
  HIGH_CONFIDENCE_PHISHING: { label: "HIGH CONFIDENCE PHISHING", color: "text-severity-critical border-severity-critical/40 bg-severity-critical/10", Icon: ShieldX },
};

export default function VerdictBanner({ verdict, score }: { verdict: Verdict; score: number }) {
  const { label, color, Icon } = CONFIG[verdict];
  return (
    <div className={clsx("flex items-center justify-between rounded-xl border p-6", color)}>
      <div className="flex items-center gap-4">
        <Icon className="h-10 w-10" />
        <div>
          <p className="text-xs uppercase tracking-wider opacity-70">Verdict</p>
          <p className="text-2xl font-semibold">{label}</p>
        </div>
      </div>
      <div className="text-right">
        <p className="text-xs uppercase tracking-wider opacity-70">Risk score</p>
        <p className="text-3xl font-bold tabular-nums">{score}/100</p>
      </div>
    </div>
  );
}
