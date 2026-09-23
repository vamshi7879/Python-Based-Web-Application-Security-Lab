import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Download,
  FileCode2,
  FileText,
  ScanLine,
  ShieldCheck,
} from "lucide-react";
import {
  analyzePython,
  buildScanReport,
  SCAN_SAMPLES,
  type ScanResult,
  type ScannerSeverity,
} from "@/lib/scanner";

export const Route = createFileRoute("/scanner")({
  head: () => ({ meta: [{ title: "Secure Coding Scanner — AppSec Lab" }] }),
  component: Scanner,
});

const severityClasses: Record<ScannerSeverity, string> = {
  Critical: "border-danger/40 bg-danger/10 text-danger",
  High: "border-orange-400/40 bg-orange-400/10 text-orange-300",
  Medium: "border-warn/40 bg-warn/10 text-warn",
  Low: "border-accent/40 bg-accent/10 text-accent",
  Informational: "border-border bg-secondary text-muted-foreground",
};

function createPdfBlob(report: string): Blob {
  const safeReport = report.replace(/[^\x20-\x7e\n\r\t]/g, "?");
  const lines: string[] = [];
  for (const line of safeReport.split(/\r?\n/)) {
    if (!line) {
      lines.push("");
      continue;
    }
    let remaining = line;
    while (remaining.length > 96) {
      const breakAt = remaining.lastIndexOf(" ", 96);
      const splitAt = breakAt > 0 ? breakAt : 96;
      lines.push(remaining.slice(0, splitAt));
      remaining = remaining.slice(splitAt).trimStart();
    }
    lines.push(remaining);
  }

  const pageLines = 48;
  const pages = Array.from(
    { length: Math.max(1, Math.ceil(lines.length / pageLines)) },
    (_, index) => lines.slice(index * pageLines, (index + 1) * pageLines),
  );
  const escapePdfText = (text: string) =>
    text.replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");
  const objects: string[] = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pages.map((_, index) => `${4 + index * 2} 0 R`).join(" ")}] /Count ${pages.length} >>`,
    "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>",
  ];

  pages.forEach((page, index) => {
    const content = ["BT", "/F1 9 Tf", "54 748 Td", "11 TL"];
    page.forEach((line, lineIndex) => {
      if (lineIndex > 0) content.push("T*");
      content.push(`(${escapePdfText(line)}) Tj`);
    });
    content.push("ET");
    const stream = content.join("\n");
    objects.push(
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents ${5 + index * 2} 0 R >>`,
      `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    );
  });

  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(pdf.length);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, "0")} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return new Blob([pdf], { type: "application/pdf" });
}

function Scanner() {
  const [source, setSource] = useState<string>(SCAN_SAMPLES.high.code);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [filter, setFilter] = useState<ScannerSeverity | "All">("All");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const selected = result?.findings.find((item) => item.id === selectedId) ?? result?.findings[0];
  const visibleFindings = useMemo(
    () => result?.findings.filter((item) => filter === "All" || item.severity === filter) ?? [],
    [filter, result],
  );

  const scan = () => {
    const next = analyzePython(source);
    setResult(next);
    setSelectedId(next.findings[0]?.id ?? null);
  };

  const loadSample = (key: keyof typeof SCAN_SAMPLES) => {
    setSource(SCAN_SAMPLES[key].code);
    setResult(null);
    setSelectedId(null);
  };

  const loadFile = async (file: File) => {
    if (!file.name.toLowerCase().endsWith(".py")) {
      setResult({ ...analyzePython(""), error: "Only .py files are accepted." });
      return;
    }
    if (file.size > 200_000) {
      setResult({
        ...analyzePython(""),
        error: "The selected file exceeds the 200 KB prototype limit.",
      });
      return;
    }
    setSource(await file.text());
    setResult(null);
  };

  const downloadReport = (format: "md" | "pdf") => {
    if (!result) return;
    const report = buildScanReport(source, result);
    const blob =
      format === "pdf"
        ? createPdfBlob(report)
        : new Blob([report], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `secure-coding-assessment.${format}`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="mx-auto max-w-7xl px-5 py-10">
      <div className="flex flex-wrap items-start justify-between gap-5">
        <div>
          <div className="flex items-center gap-2 font-mono text-xs text-primary">
            <ScanLine className="size-4" /> DEFENSIVE STATIC ANALYSIS
          </div>
          <h1 className="mt-3 text-3xl font-bold sm:text-4xl">
            Secure Coding <span className="text-primary">Scanner</span>
          </h1>
          <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
            Review untrusted Python source for explainable secure-coding patterns. The browser reads
            text only: it never executes, imports, or sends submitted code anywhere.
          </p>
        </div>
        <div className="flex items-center gap-2 rounded-md border border-ok/30 bg-ok/10 px-3 py-2 font-mono text-[11px] text-ok">
          <ShieldCheck className="size-4" /> CODE NEVER EXECUTES
        </div>
      </div>

      <div className="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(360px,.9fr)]">
        <section className="rounded-xl border border-border bg-card/60 p-5">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="font-semibold">Source input</h2>
              <p className="mt-1 text-xs text-muted-foreground">
                Paste code, load a sample, or choose a local `.py` file.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {(Object.keys(SCAN_SAMPLES) as Array<keyof typeof SCAN_SAMPLES>).map((key) => (
                <button
                  key={key}
                  onClick={() => loadSample(key)}
                  className="rounded-md border border-border px-2.5 py-1.5 font-mono text-[11px] hover:border-primary/60 hover:text-primary"
                >
                  {SCAN_SAMPLES[key].name}
                </button>
              ))}
            </div>
          </div>
          <textarea
            value={source}
            onChange={(event) => setSource(event.target.value)}
            spellCheck={false}
            className="mt-4 min-h-[430px] w-full resize-y rounded-lg border border-border bg-terminal p-4 font-mono text-[12px] leading-relaxed text-foreground outline-none focus:border-primary"
            aria-label="Python source code"
          />
          <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
            <div className="flex gap-2">
              <input
                ref={fileRef}
                type="file"
                accept=".py,text/x-python"
                className="hidden"
                onChange={(event) =>
                  event.target.files?.[0] && void loadFile(event.target.files[0])
                }
              />
              <button
                onClick={() => fileRef.current?.click()}
                className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-secondary"
              >
                <FileCode2 className="size-4" /> Upload .py
              </button>
              <button
                onClick={() => {
                  setSource("");
                  setResult(null);
                }}
                className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-secondary"
              >
                <Clipboard className="size-4" /> Clear
              </button>
            </div>
            <button
              onClick={scan}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-5 py-2 text-sm font-semibold text-primary-foreground hover:opacity-90"
            >
              <ScanLine className="size-4" /> Analyze source
            </button>
          </div>
        </section>

        <section className="space-y-4">
          <Summary result={result} onDownload={downloadReport} />
          {result?.error && (
            <div className="flex gap-3 rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm text-danger">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <div>
                <strong>Analysis could not be completed.</strong>
                <p className="mt-1 text-danger/80">{result.error}</p>
              </div>
            </div>
          )}
          {result && !result.error && (
            <>
              <div className="rounded-xl border border-border bg-card/60 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="font-semibold">Findings</h2>
                  <select
                    value={filter}
                    onChange={(event) => setFilter(event.target.value as ScannerSeverity | "All")}
                    className="rounded-md border border-input bg-secondary px-2 py-1.5 font-mono text-[11px]"
                  >
                    <option>All</option>
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                    <option>Informational</option>
                  </select>
                </div>
                <div className="mt-3 space-y-2">
                  {visibleFindings.length ? (
                    visibleFindings.map((item) => (
                      <button
                        key={item.id}
                        onClick={() => setSelectedId(item.id)}
                        className={`w-full rounded-lg border p-3 text-left transition-colors ${selected?.id === item.id ? "border-primary/60 bg-primary/10" : "border-border bg-secondary/30 hover:bg-secondary/70"}`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs text-primary">
                            {item.id} · line {item.line}
                          </span>
                          <span
                            className={`rounded-full border px-2 py-0.5 font-mono text-[10px] ${severityClasses[item.severity]}`}
                          >
                            {item.severity}
                          </span>
                        </div>
                        <div className="mt-1 text-sm font-medium">{item.title}</div>
                        <div className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
                          {item.detectedPattern}
                        </div>
                      </button>
                    ))
                  ) : (
                    <p className="py-4 text-sm text-muted-foreground">
                      No findings match this filter.
                    </p>
                  )}
                </div>
              </div>
              {selected && <FindingDetail finding={selected} sourceLines={result.lines} />}
            </>
          )}
          {!result && (
            <div className="rounded-xl border border-dashed border-border bg-card/30 p-8 text-center text-sm text-muted-foreground">
              <ScanLine className="mx-auto size-8 text-primary/70" />
              <p className="mt-3">
                Your normalized findings, risk summary, and remediation details will appear here.
              </p>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

function Summary({
  result,
  onDownload,
}: {
  result: ScanResult | null;
  onDownload: (format: "md" | "pdf") => void;
}) {
  const total = result?.findings.length ?? 0;
  return (
    <div className="rounded-xl border border-border bg-card/60 p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-mono text-[11px] text-muted-foreground">ASSESSMENT SUMMARY</div>
          <div className="mt-2 text-4xl font-bold text-primary">
            {result ? result.score : "--"}
            <span className="text-lg text-muted-foreground"> / 100</span>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            Educational static-analysis score, not a certification.
          </p>
        </div>
        {result && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => onDownload("md")}
              title="Download Markdown report"
              aria-label="Download Markdown report"
              className="rounded-md border border-border p-2 hover:bg-secondary"
            >
              <Download className="size-4" />
            </button>
            <button
              onClick={() => onDownload("pdf")}
              title="Download PDF security report"
              aria-label="Download PDF security report"
              className="rounded-md border border-border p-2 hover:bg-secondary"
            >
              <FileText className="size-4" />
            </button>
          </div>
        )}
      </div>
      <div className="mt-5 grid grid-cols-2 gap-2 sm:grid-cols-5">
        {(["Critical", "High", "Medium", "Low", "Informational"] as ScannerSeverity[]).map(
          (severity) => (
            <div key={severity} className={`rounded-md border p-2 ${severityClasses[severity]}`}>
              <div className="font-mono text-lg font-bold">{result?.summary[severity] ?? 0}</div>
              <div className="text-[10px]">{severity}</div>
            </div>
          ),
        )}
      </div>
      <div className="mt-4 flex items-center gap-2 text-xs text-muted-foreground">
        {result ? (
          <>
            <CheckCircle2 className="size-4 text-ok" />{" "}
            {total
              ? `${total} potential finding${total === 1 ? "" : "s"} require review.`
              : "No configured high-risk patterns detected."}
          </>
        ) : (
          "Ready for source analysis."
        )}
      </div>
    </div>
  );
}

function FindingDetail({
  finding,
  sourceLines,
}: {
  finding: NonNullable<ScanResult["findings"]>[number];
  sourceLines: string[];
}) {
  return (
    <article className="rounded-xl border border-border bg-card/60 p-5">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <div className="font-mono text-xs text-primary">
            {finding.id} · priority {finding.priority}
          </div>
          <h2 className="mt-1 text-lg font-semibold">{finding.title}</h2>
        </div>
        <span
          className={`rounded-full border px-2 py-1 font-mono text-[11px] ${severityClasses[finding.severity]}`}
        >
          {finding.severity} · {finding.confidence} confidence
        </span>
      </div>
      <div className="mt-4 rounded-md border border-border bg-terminal p-3 font-mono text-[11px] text-muted-foreground">
        <span className="mr-3 text-primary">{String(finding.line).padStart(3, "0")}</span>
        {sourceLines[finding.line - 1]}
      </div>
      <dl className="mt-4 space-y-3 text-sm">
        <div>
          <dt className="font-semibold">Why it matters</dt>
          <dd className="mt-1 text-muted-foreground">
            {finding.description} {finding.impact}
          </dd>
        </div>
        <div>
          <dt className="font-semibold">Recommended fix</dt>
          <dd className="mt-1 text-muted-foreground">{finding.recommendation}</dd>
        </div>
        <div>
          <dt className="font-semibold">Principles</dt>
          <dd className="mt-1 text-muted-foreground">{finding.principles.join(" · ")}</dd>
        </div>
      </dl>
      <pre className="mt-4 overflow-auto rounded-md border border-ok/20 bg-ok/5 p-3 font-mono text-[11px] leading-relaxed text-ok">
        {finding.secureExample}
      </pre>
    </article>
  );
}
