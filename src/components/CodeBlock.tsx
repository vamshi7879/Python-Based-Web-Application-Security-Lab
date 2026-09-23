import { cn } from "@/lib/utils";

export function CodeBlock({
  title,
  code,
  variant,
}: {
  title: string;
  code: string;
  variant: "before" | "after";
}) {
  const lines = code.split("\n");
  return (
    <div
      className={cn(
        "overflow-hidden rounded-lg border bg-terminal",
        variant === "before" ? "border-danger/35" : "border-ok/35",
      )}
    >
      <div
        className={cn(
          "border-b px-3 py-2 font-mono text-[11px] font-semibold tracking-wide uppercase",
          variant === "before"
            ? "border-danger/25 bg-danger/10 text-danger"
            : "border-ok/25 bg-ok/10 text-ok",
        )}
      >
        {title}
      </div>
      <pre className="overflow-auto p-4 font-mono text-[12px] leading-relaxed">
        {lines.map((l, i) => (
          <div key={i} className="flex gap-3">
            <span className="w-6 shrink-0 text-right text-muted-foreground/50 select-none">
              {i + 1}
            </span>
            <span
              className={cn(
                "whitespace-pre",
                /VULNERABLE|shell=True|except:|fails open/.test(l) && "text-danger",
                /is_relative_to|shell=False|argon2|Argon2|0o600|O_EXCL|pip-audit|allow|validate|path jail|constant time/i.test(
                  l,
                ) && variant === "after"
                  ? "text-ok"
                  : "",
                l.trim().startsWith("#") && "text-muted-foreground",
              )}
            >
              {l || " "}
            </span>
          </div>
        ))}
      </pre>
    </div>
  );
}
