import { ReactNode } from "react";

export default function Card({ title, children, className }: { title?: string; children: ReactNode; className?: string }) {
  return (
    <section className={`rounded-lg border border-soc-panelBorder bg-soc-panel p-5 ${className ?? ""}`}>
      {title && <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-soc-muted">{title}</h2>}
      {children}
    </section>
  );
}
