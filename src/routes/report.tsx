import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Download, Copy, Printer, Check } from "lucide-react";
import { VULNS, PRINCIPLES } from "@/data/vulns";

export const Route = createFileRoute("/report")({
  head: () => ({
    meta: [
      { title: "Security Assessment Report — Python Web Application Security Case Study" },
      {
        name: "description",
        content:
          "Educational security assessment report for six Python web application secure-coding weaknesses.",
      },
      { property: "og:title", content: "Security Assessment Report" },
      {
        property: "og:description",
        content:
          "Executive summary, finding register and remediation evidence, exportable as Markdown or PDF.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Report,
});

function buildMarkdown() {
  return `# Security Assessment Report
**Case Study:** Python Web Application Security Case Study
**Scope:** Educational browser-based simulation of a Python web application scenario
**Status:** Case Study Complete — 6 of 6 weaknesses addressed in the educational simulation

## 1. Executive Summary
A security review identified six secure-coding weaknesses involving user input, file handling,
commands, credentials, temporary files, exceptions, and dependencies. The case study presents
risk assessment, prioritization, representative Python remediation, and controlled browser
demonstrations. No backend commands, filesystem operations, production database, or Python CI
workflow are executed by this frontend.

## 2. Case Study and Six Findings
The six findings are listed in priority order in the application finding register.

## 2. Finding Register
| Priority | CWE | Finding | Likelihood | Impact | Overall Risk | Reason |
|----------|-----|---------|------------|--------|--------------|--------|
${VULNS.map(
  (v, i) =>
    `| ${v.priority} | ${v.cwe} | ${v.title} | ${v.likelihood} | ${v.impactRating} | ${v.overallRisk} | ${v.reason} |`,
).join("\n")}

## 3. Risk Assessment and Prioritization
| Priority | Weakness | CWE | Likelihood | Impact | Overall Risk | Reason |
|---|---|---|---|---|---|---|
${VULNS.map((v) => `| ${v.priority} | ${v.title} | ${v.cwe} | ${v.likelihood} | ${v.impactRating} | ${v.overallRisk} | ${v.reason} |`).join("\n")}

## 4. Remediation and Detailed Findings
${VULNS.map(
  (v, i) => `### VULN-0${i + 1} — ${v.title} (${v.cwe})
- **Risk:** ${v.likelihood} likelihood; ${v.impactRating} impact; ${v.overallRisk} overall; priority ${v.priority}
- **Location:** \`${v.file}\`
- **Description:** ${v.summary}

**Impact**
${v.impact.map((x) => `- ${x}`).join("\n")}

**Remediation**
${v.fix.map((x) => `- ${x}`).join("\n")}

**Before**
\`\`\`python
${v.before}
\`\`\`

**After**
\`\`\`python
${v.after}
\`\`\`

**Principles applied:** ${v.principles.join(", ")}
**Validation:** ${v.validation}
`,
).join("\n")}

## 5. Secure Coding Principles
${PRINCIPLES.map((p) => `- **${p.name}** — ${p.body} Applies to: ${p.applies.join(", ")} Demonstrated by: ${p.applied}`).join("\n")}

## 6. DevSecOps Simulation
The pipeline page provides simulated formatting/linting, static analysis, dependency scanning,
security regression, security gate, and build/release decision stages. It does not run Bandit,
pip-audit, pytest, or a CI workflow in this frontend.

## 7. Limitations
The current frontend is a browser simulation. It does not execute attacker-supplied operating-
system commands, access the host filesystem, upload real files, connect to a production database,
or produce actual test coverage.

## 8. Conclusion
The laboratory demonstrates identification, evaluation, prioritization, secure coding
recommendations, and critical justification through representative examples.

_Prepared by the Python Web Application Security Case Study educational laboratory._
`;
}

function Report() {
  const md = buildMarkdown();
  const [copied, setCopied] = useState(false);

  const download = (ext: "md" | "txt") => {
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `security-assessment-report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copy = async () => {
    await navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };

  return (
    <div className="mx-auto max-w-5xl px-5 py-10">
      <h1 className="text-3xl font-bold">
        Security Assessment <span className="text-primary">Report</span>
      </h1>
      <p className="mt-2 text-sm text-muted-foreground">
        Portfolio-ready deliverable: executive summary, full finding register, code evidence and
        DevSecOps controls.
      </p>

      <div className="mt-6 flex flex-wrap gap-3 print:hidden">
        <button
          onClick={() => download("md")}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:opacity-90"
        >
          <Download className="size-4" /> Markdown
        </button>
        <button
          onClick={() => window.print()}
          className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm hover:bg-secondary"
        >
          <Printer className="size-4" /> Print / Save as PDF
        </button>
        <button
          onClick={copy}
          className="inline-flex items-center gap-2 rounded-md border border-border px-4 py-2 text-sm hover:bg-secondary"
        >
          {copied ? <Check className="size-4 text-ok" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Copy README"}
        </button>
      </div>

      <div className="mt-8 grid gap-4 sm:grid-cols-3 print:hidden">
        {[
          { k: "Findings", v: "6" },
          { k: "Findings addressed", v: "6/6" },
          { k: "Validation", v: "Simulated" },
        ].map((m) => (
          <div key={m.k} className="rounded-xl border border-border bg-card/60 p-4">
            <div className="font-mono text-2xl font-bold text-primary">{m.v}</div>
            <div className="text-xs text-muted-foreground">{m.k}</div>
          </div>
        ))}
      </div>

      <div className="mt-8 overflow-hidden rounded-xl border border-border bg-terminal">
        <div className="border-b border-border/60 bg-card/60 px-4 py-2 font-mono text-[11px] text-muted-foreground">
          SECURITY-ASSESSMENT-REPORT.md
        </div>
        <pre className="max-h-[70vh] overflow-auto p-5 font-mono text-[12px] leading-relaxed whitespace-pre-wrap">
          {md}
        </pre>
      </div>
    </div>
  );
}
