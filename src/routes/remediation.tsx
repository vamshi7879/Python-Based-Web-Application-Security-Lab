import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { VULNS, PRINCIPLES, severityColor } from "@/data/vulns";
import { CodeBlock } from "@/components/CodeBlock";
import { Chip } from "@/components/Badge";

export const Route = createFileRoute("/remediation")({
  head: () => ({
    meta: [
      { title: "Remediation Inspector — AppSec Hardening Lab" },
      {
        name: "description",
        content:
          "Side-by-side insecure vs hardened Python for all six findings, mapped to Saltzer & Schroeder secure design principles.",
      },
      { property: "og:title", content: "Code Diff & Remediation Inspector" },
      {
        property: "og:description",
        content:
          "Before/after code for every finding plus the secure design principles behind each fix.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Remediation,
});

function Remediation() {
  const [openId, setOpenId] = useState(VULNS[0]!.id);

  return (
    <div className="mx-auto max-w-7xl px-5 py-10">
      <h1 className="text-3xl font-bold">
        Remediation <span className="text-primary">Inspector</span>
      </h1>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
        Representative vulnerable and hardened Python examples for each case-study finding.
      </p>

      <div className="mt-8 space-y-4">
        {VULNS.map((v, i) => {
          const open = openId === v.id;
          return (
            <div key={v.id} className="overflow-hidden rounded-xl border border-border bg-card/60">
              <button
                onClick={() => setOpenId(open ? "" : v.id)}
                className="flex w-full flex-wrap items-center gap-3 px-5 py-4 text-left hover:bg-secondary/40"
              >
                <span className="font-mono text-[11px] text-muted-foreground">VULN-0{i + 1}</span>
                <span className="font-semibold">{v.title}</span>
                <Chip>{v.cwe}</Chip>
                <span
                  className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${severityColor(v.severity)}`}
                >
                  {v.overallRisk} risk · Priority {v.priority}
                </span>
                <span className="ml-auto font-mono text-xs text-primary">
                  {open ? "collapse −" : "expand +"}
                </span>
              </button>
              {open ? (
                <div className="border-t border-border/60 p-5">
                  <div className="grid gap-4 xl:grid-cols-2">
                    <CodeBlock title={`before — ${v.file}`} code={v.before} variant="before" />
                    <CodeBlock title={`after — ${v.file}`} code={v.after} variant="after" />
                  </div>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {v.principles.map((p) => (
                      <Chip key={p} className="border-primary/40 bg-primary/10 text-primary">
                        {p}
                      </Chip>
                    ))}
                  </div>
                  <div className="mt-4 grid gap-2 text-sm text-muted-foreground md:grid-cols-2">
                    <p>
                      <strong className="text-foreground">Why the change matters:</strong>{" "}
                      {v.remediation}
                    </p>
                    <p>
                      <strong className="text-foreground">Principle:</strong>{" "}
                      {v.principles.join(", ")}
                    </p>
                    <p>
                      <strong className="text-foreground">Verification:</strong> {v.validation}
                    </p>
                    <p>
                      <strong className="text-foreground">Risk:</strong> {v.likelihood} likelihood,{" "}
                      {v.impactRating} impact, {v.overallRisk} overall risk. Priority {v.priority}.
                    </p>
                  </div>
                </div>
              ) : null}
            </div>
          );
        })}
      </div>

      <h2 className="mt-14 text-2xl font-bold">Secure design principles applied</h2>
      <div className="mt-5 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {PRINCIPLES.map((p) => (
          <div key={p.name} className="rounded-xl border border-border bg-card/60 p-5">
            <div className="font-semibold text-primary">{p.name}</div>
            <p className="mt-2 text-[13px] text-muted-foreground">{p.body}</p>
            <div className="mt-3 rounded-md border border-border/60 bg-terminal p-3 font-mono text-[11px] text-muted-foreground">
              {p.applied}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
