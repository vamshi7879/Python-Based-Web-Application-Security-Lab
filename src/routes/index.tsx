import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowRight, Activity, Bug, GitBranch, Lock } from "lucide-react";
import { VULNS, severityColor } from "@/data/vulns";
import { Chip, Metric } from "@/components/Badge";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Python Web Application Security Case Study" },
      {
        name: "description",
        content:
          "Educational browser-based laboratory for a Python web application security case study with six secure-coding weaknesses.",
      },
      { property: "og:title", content: "AppSec Hardening Lab — Cybersecurity Portfolio" },
      {
        property: "og:description",
        content:
          "Controlled simulations, representative Python examples, risk assessment, remediation, and simulated DevSecOps validation.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

function Dashboard() {
  const critical = VULNS.filter((v) => v.severity === "Critical").length;

  return (
    <div>
      <section className="relative overflow-hidden border-b border-border/60 grid-backdrop">
        <div className="mx-auto max-w-7xl px-5 py-20">
          <Chip className="border-ok/40 bg-ok/10 text-ok">
            educational security case study · controlled simulation
          </Chip>
          <h1 className="mt-5 max-w-3xl text-4xl leading-tight font-bold sm:text-6xl">
            Python Web Application Security <span className="text-primary">Case Study</span>
          </h1>
          <p className="mt-5 max-w-2xl text-muted-foreground">
            A Python-based web application accepts user input, processes files supplied by users,
            executes system commands, and stores user credentials. A security review identified six
            secure-coding weaknesses requiring remediation.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link
              to="/lab"
              className="inline-flex items-center gap-2 rounded-md bg-primary px-5 py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 glow-primary"
            >
              Launch exploit sandbox <ArrowRight className="size-4" />
            </Link>
            <Link
              to="/remediation"
              className="inline-flex items-center gap-2 rounded-md border border-border bg-card/60 px-5 py-2.5 text-sm font-semibold transition-colors hover:bg-secondary"
            >
              Inspect code diffs
            </Link>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 py-12">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Metric
            value="6"
            label="Security weaknesses"
            hint={`${critical} critical`}
            tone="danger"
          />
          <Metric
            value="6"
            label="Remediation paths"
            hint="representative Python examples"
            tone="ok"
          />
          <Metric
            value="6"
            label="Secure coding principles"
            hint="mapped across findings"
            tone="warn"
          />
          <Metric
            value="Browser"
            label="Educational simulation"
            hint="no real backend or filesystem"
          />
        </div>

        <div className="mt-10 grid gap-4 lg:grid-cols-3">
          <InfoCard
            icon={<Bug className="size-4 text-danger" />}
            title="OWASP Top 10 coverage"
            items={[
              "A01 Broken Access Control",
              "A02 Cryptographic Failures",
              "A03 Injection",
              "A04 Insecure Design",
              "A06 Vulnerable Components",
              "A09 Logging Failures",
            ]}
          />
          <InfoCard
            icon={<Activity className="size-4 text-accent" />}
            title="Contextual ATT&CK relationships"
            items={[...new Set(VULNS.map((v) => v.mitre))]}
          />
          <InfoCard
            icon={<Lock className="size-4 text-ok" />}
            title="Controls introduced"
            items={[
              "Argon2id credential hashing",
              "Argument vectorization (shell=False)",
              "Upload path jail + UUID storage",
              "Atomic 0600 temp files",
              "Structured, sanitized error handling",
              "Simulated dependency and static-analysis gates",
            ]}
          />
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-12">
        <h2 className="text-2xl font-bold">Security Assessment Objectives</h2>
        <ul className="mt-4 grid gap-3 text-sm text-muted-foreground sm:grid-cols-2 lg:grid-cols-3">
          {[
            "Identify security weaknesses.",
            "Evaluate likelihood and impact.",
            "Prioritize risks.",
            "Recommend secure coding practices.",
            "Justify remediation using secure coding principles.",
            "Demonstrate vulnerable and hardened implementations.",
          ].map((objective) => (
            <li key={objective} className="rounded-lg border border-border bg-card/60 p-4">
              {objective}
            </li>
          ))}
        </ul>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-12">
        <h2 className="text-2xl font-bold">Assessment / Rubric Coverage</h2>
        <p className="mt-2 text-sm text-muted-foreground">Evidence provided in this laboratory:</p>
        <div className="mt-4 grid gap-3 md:grid-cols-2 lg:grid-cols-5">
          {[
            "Identification of Security Weaknesses — 2 Marks",
            "Evaluation & Risk Assessment — 2 Marks",
            "Prioritization — 2 Marks",
            "Secure Coding Recommendations — 2 Marks",
            "Critical Justification & Defense — 2 Marks",
          ].map((criterion, index) => (
            <div key={criterion} className="rounded-lg border border-border bg-card/60 p-4">
              <div className="font-mono text-xs text-primary">{index + 1}</div>
              <div className="mt-2 text-sm font-semibold">{criterion}</div>
              <p className="mt-2 text-xs text-muted-foreground">
                {
                  [
                    "Finding register and six CWE modules.",
                    "Likelihood, impact, risk, and scenario details.",
                    "Priority order and rationale table.",
                    "Before/after examples and remediation guidance.",
                    "Principles, limitations, and controlled demonstrations.",
                  ][index]
                }
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-20">
        <div className="mb-4 flex items-center gap-2">
          <GitBranch className="size-4 text-primary" />
          <h2 className="text-xl font-bold">Finding register</h2>
        </div>
        <div className="overflow-hidden rounded-xl border border-border bg-card/60">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border bg-secondary/40 font-mono text-[11px] tracking-wide text-muted-foreground uppercase">
              <tr>
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Priority</th>
                <th className="hidden px-4 py-3 md:table-cell">OWASP</th>
                <th className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {VULNS.map((v, i) => (
                <tr key={v.id} className="border-b border-border/50 last:border-0">
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    VULN-0{i + 1} · {v.cwe}
                  </td>
                  <td className="px-4 py-3">
                    <Link to="/lab" search={{ v: v.id }} className="font-medium hover:text-primary">
                      {v.title}
                    </Link>
                  </td>
                  <td className="px-4 py-3 font-mono">{v.overallRisk}</td>
                  <td className="px-4 py-3">
                    <span
                      className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${severityColor(v.severity)}`}
                    >
                      {v.priority}
                    </span>
                  </td>
                  <td className="hidden px-4 py-3 text-xs text-muted-foreground md:table-cell">
                    {v.owasp}
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-ok">FIXED</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function InfoCard({
  icon,
  title,
  items,
}: {
  icon: React.ReactNode;
  title: string;
  items: string[];
}) {
  return (
    <div className="rounded-xl border border-border bg-card/60 p-5">
      <div className="flex items-center gap-2 text-sm font-semibold">
        {icon}
        {title}
      </div>
      <ul className="mt-3 space-y-1.5 font-mono text-[12px] text-muted-foreground">
        {items.map((i) => (
          <li key={i} className="flex gap-2">
            <span className="text-primary">›</span>
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}
