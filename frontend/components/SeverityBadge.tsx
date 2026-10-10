import clsx from "clsx";
import { Severity } from "@/types/analysis";

const STYLES: Record<Severity, string> = {
  CRITICAL: "bg-severity-critical/15 text-severity-critical border-severity-critical/40",
  HIGH: "bg-severity-high/15 text-severity-high border-severity-high/40",
  MEDIUM: "bg-severity-medium/15 text-severity-medium border-severity-medium/40",
  LOW: "bg-severity-low/15 text-severity-low border-severity-low/40",
};

export default function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium tracking-wide",
        STYLES[severity]
      )}
    >
      {severity}
    </span>
  );
}
