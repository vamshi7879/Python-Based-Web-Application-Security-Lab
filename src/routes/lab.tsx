import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import { VULNS, severityColor } from "@/data/vulns";
import { simulate, type SimResult } from "@/lib/simulate";
import { Terminal } from "@/components/Terminal";
import { Chip } from "@/components/Badge";

type Search = { v?: string };

export const Route = createFileRoute("/lab")({
  validateSearch: (s: Record<string, unknown>): Search =>
    typeof s["v"] === "string" ? { v: s["v"] } : {},
  head: () => ({
    meta: [
      { title: "Exploit Sandbox — AppSec Hardening Lab" },
      {
        name: "description",
        content:
          "Run live payloads against vulnerable and hardened builds side by side: command injection, path traversal, credential storage, temp files, error handling and SCA.",
      },
      { property: "og:title", content: "Interactive Exploit Sandbox" },
      {
        property: "og:description",
        content:
          "Evaluate payloads in a simulated educational environment against vulnerable and hardened Python code.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Lab,
});

function Lab() {
  const { v } = Route.useSearch();
  const [activeId, setActiveId] = useState(v && VULNS.some((x) => x.id === v) ? v : VULNS[0]!.id);
  const active = useMemo(() => VULNS.find((x) => x.id === activeId)!, [activeId]);
  const [input, setInput] = useState(active.samplePayloads[0]!);
  const [runs, setRuns] = useState<{ bad: SimResult; good: SimResult } | null>(null);

  const select = (id: string) => {
    const vuln = VULNS.find((x) => x.id === id)!;
    setActiveId(id);
    setInput(vuln.samplePayloads[0]!);
    setRuns(null);
  };

  const run = () => {
    const id = active.id;
    const value = input;
    void Promise.all([simulate(id, value, false), simulate(id, value, true)]).then(([bad, good]) =>
      setRuns({ bad, good }),
    );
  };

  return (
    <div className="mx-auto max-w-7xl px-5 py-10">
      <h1 className="text-3xl font-bold">
        Exploit <span className="text-primary">Sandbox</span>
      </h1>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
        Fire the same payload at both builds. The left terminal runs the original insecure code; the
        right runs the hardened remediation. All execution is simulated — nothing leaves your
        browser.
      </p>
      <div className="mt-4 inline-flex items-center gap-2 rounded-md border border-warn/40 bg-warn/10 px-3 py-2 font-mono text-[11px] text-warn">
        SIMULATED EDUCATIONAL ENVIRONMENT · NO COMMANDS OR PAYLOADS REACH AN EXTERNAL SYSTEM
      </div>

      <div className="mt-8 grid gap-6 lg:grid-cols-[260px_1fr]">
        <aside className="space-y-2">
          {VULNS.map((x, i) => (
            <button
              key={x.id}
              onClick={() => select(x.id)}
              className={`w-full rounded-lg border px-3 py-3 text-left transition-colors ${
                x.id === activeId
                  ? "border-primary/50 bg-primary/10"
                  : "border-border bg-card/50 hover:bg-secondary/60"
              }`}
            >
              <div className="font-mono text-[10px] text-muted-foreground">
                MODULE 0{i + 1} · {x.cwe}
              </div>
              <div className="mt-0.5 text-sm font-medium">{x.short}</div>
            </button>
          ))}
        </aside>

        <div>
          <div className="rounded-xl border border-border bg-card/60 p-5">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-bold">{active.title}</h2>
              <span
                className={`rounded-full border px-2 py-0.5 font-mono text-[11px] ${severityColor(active.severity)}`}
              >
                {active.overallRisk} risk · Priority {active.priority}
              </span>
              <Chip>{active.cwe}</Chip>
              <Chip>{active.owasp}</Chip>
              <Chip>{active.mitre}</Chip>
            </div>
            <p className="mt-3 text-sm text-muted-foreground">{active.summary}</p>
            <div className="mt-4 grid gap-3 text-sm md:grid-cols-2">
              <div>
                <strong>Weakness:</strong>{" "}
                <span className="text-muted-foreground">{active.weakness}</span>
              </div>
              <div>
                <strong>Why it is dangerous:</strong>{" "}
                <span className="text-muted-foreground">{active.danger}</span>
              </div>
              <div>
                <strong>Attack / failure scenario:</strong>{" "}
                <span className="text-muted-foreground">{active.scenario}</span>
              </div>
              <div>
                <strong>Risk assessment:</strong>{" "}
                <span className="text-muted-foreground">
                  Likelihood {active.likelihood}; impact {active.impactRating}; overall{" "}
                  {active.overallRisk}.
                </span>
              </div>
            </div>
            <div className="mt-2 font-mono text-[11px] text-muted-foreground">
              representative source: {active.file}
              {active.vector ? ` · ${active.vector}` : ""}
            </div>
            <p className="mt-3 rounded-md border border-warn/30 bg-warn/10 p-3 text-xs text-warn">
              {active.simulationNotice}
            </p>

            <label className="mt-5 block font-mono text-[11px] text-muted-foreground uppercase">
              {active.inputLabel}
            </label>
            <div className="mt-2 flex flex-wrap gap-2">
              <input
                value={input}
                maxLength={200}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && run()}
                className="min-w-0 flex-1 rounded-md border border-input bg-terminal px-3 py-2 font-mono text-sm outline-none focus:border-primary"
                placeholder="enter payload…"
              />
              <button
                onClick={run}
                className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:opacity-90"
              >
                <Play className="size-4" /> Execute
              </button>
              <button
                onClick={() => {
                  setInput(active.samplePayloads[0]!);
                  setRuns(null);
                }}
                className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-secondary"
              >
                <RotateCcw className="size-4" />
              </button>
            </div>
            <div className="mt-3 flex flex-wrap gap-2">
              {active.samplePayloads.map((p) => (
                <button
                  key={p}
                  onClick={() => setInput(p)}
                  className="rounded-full border border-border bg-secondary/50 px-3 py-1 font-mono text-[11px] text-muted-foreground hover:border-primary/50 hover:text-primary"
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-2">
            <div>
              <Verdict label="Vulnerable build" verdict={runs?.bad.verdict} tone="bad" />
              <Terminal
                title={`vulnerable@appsec:~ ${active.file}`}
                variant="vulnerable"
                lines={runs?.bad.lines ?? [{ text: "awaiting payload…", tone: "dim" }]}
              />
            </div>
            <div>
              <Verdict label="Hardened build" verdict={runs?.good.verdict} tone="good" />
              <Terminal
                title={`hardened@appsec:~ ${active.file}`}
                lines={runs?.good.lines ?? [{ text: "awaiting payload…", tone: "dim" }]}
              />
            </div>
          </div>

          <div className="mt-6 grid gap-4 md:grid-cols-2">
            <ListCard title="Business impact if unpatched" items={active.impact} tone="bad" />
            <ListCard title="Controls applied" items={active.fix} tone="good" />
          </div>
          <div className="mt-4 rounded-xl border border-border bg-card/60 p-5 text-sm">
            <div>
              <strong>Secure coding principle:</strong>{" "}
              <span className="text-muted-foreground">{active.principles.join(", ")}</span>
            </div>
            <div className="mt-2">
              <strong>Recommended remediation:</strong>{" "}
              <span className="text-muted-foreground">{active.remediation}</span>
            </div>
            <div className="mt-2">
              <strong>Validation / demonstration:</strong>{" "}
              <span className="text-muted-foreground">{active.validation}</span>
            </div>
            <div className="mt-2">
              <strong>Priority:</strong>{" "}
              <span className="text-muted-foreground">
                {active.priority} - {active.reason}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Verdict({
  label,
  verdict,
  tone,
}: {
  label: string;
  verdict?: string | undefined;
  tone: "bad" | "good";
}) {
  const vulnerableLabel =
    verdict === "safe" || verdict === "benign"
      ? "BENIGN INPUT"
      : verdict === "exposed"
        ? "EXPOSED"
        : verdict;
  const display = tone === "bad" ? vulnerableLabel : verdict;
  const color =
    display === "exploited" || display === "EXPOSED"
      ? "text-danger"
      : display
        ? tone === "bad" && display === "BENIGN INPUT"
          ? "text-warn"
          : "text-ok"
        : "text-muted-foreground";
  return (
    <div className="mb-2 flex items-center justify-between">
      <span className={`text-sm font-semibold ${tone === "bad" ? "text-danger" : "text-ok"}`}>
        {label}
      </span>
      <span className={`font-mono text-[11px] uppercase ${color}`}>{display ?? "idle"}</span>
    </div>
  );
}

function ListCard({
  title,
  items,
  tone,
}: {
  title: string;
  items: string[];
  tone: "bad" | "good";
}) {
  return (
    <div
      className={`rounded-xl border p-5 ${tone === "bad" ? "border-danger/30 bg-danger/5" : "border-ok/30 bg-ok/5"}`}
    >
      <div className="text-sm font-semibold">{title}</div>
      <ul className="mt-3 space-y-1.5 text-[13px] text-muted-foreground">
        {items.map((i) => (
          <li key={i} className="flex gap-2">
            <span className={tone === "bad" ? "text-danger" : "text-ok"}>›</span>
            {i}
          </li>
        ))}
      </ul>
    </div>
  );
}
