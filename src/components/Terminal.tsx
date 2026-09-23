import { cn } from "@/lib/utils";
import type { Line } from "@/lib/simulate";

const toneClass: Record<string, string> = {
  cmd: "text-primary",
  ok: "text-ok",
  bad: "text-danger",
  warn: "text-warn",
  dim: "text-muted-foreground",
};

export function Terminal({
  title,
  lines,
  variant = "safe",
  className,
}: {
  title: string;
  lines: Line[];
  variant?: "vulnerable" | "safe";
  className?: string;
}) {
  return (
    <div
      className={cn(
        "relative overflow-hidden rounded-lg border bg-terminal scanlines",
        variant === "vulnerable" ? "border-danger/40" : "border-ok/40",
        className,
      )}
    >
      <div className="flex items-center gap-2 border-b border-border/60 bg-card/60 px-3 py-2">
        <span className="size-2.5 rounded-full bg-danger/70" />
        <span className="size-2.5 rounded-full bg-warn/70" />
        <span className="size-2.5 rounded-full bg-ok/70" />
        <span className="ml-2 font-mono text-[11px] text-muted-foreground">{title}</span>
      </div>
      <pre className="max-h-80 min-h-40 overflow-auto p-4 font-mono text-[12px] leading-relaxed whitespace-pre-wrap">
        {lines.map((l, i) => (
          <div key={i} className={toneClass[l.tone ?? "dim"]}>
            {l.text}
          </div>
        ))}
        <span className="inline-block h-3.5 w-2 animate-pulse bg-primary align-middle" />
      </pre>
    </div>
  );
}
