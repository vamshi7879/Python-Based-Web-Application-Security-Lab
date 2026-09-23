import { cn } from "@/lib/utils";
import type { ReactNode } from "react";

export function Chip({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border bg-secondary/60 px-2.5 py-0.5 font-mono text-[11px] text-muted-foreground",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Metric({
  value,
  label,
  hint,
  tone = "primary",
}: {
  value: string;
  label: string;
  hint?: string;
  tone?: "primary" | "danger" | "warn" | "ok";
}) {
  const toneClass = {
    primary: "text-primary",
    danger: "text-danger",
    warn: "text-warn",
    ok: "text-ok",
  }[tone];
  return (
    <div className="rounded-xl border border-border bg-card/70 p-5 backdrop-blur">
      <div className={cn("font-mono text-3xl font-bold", toneClass)}>{value}</div>
      <div className="mt-1 text-sm font-medium">{label}</div>
      {hint ? <div className="mt-1 text-xs text-muted-foreground">{hint}</div> : null}
    </div>
  );
}
