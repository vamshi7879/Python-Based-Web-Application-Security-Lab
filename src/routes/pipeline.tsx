import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Play, RotateCcw } from "lucide-react";
import { Terminal } from "@/components/Terminal";
import type { Line } from "@/lib/simulate";

export const Route = createFileRoute("/pipeline")({
  head: () => ({
    meta: [
      { title: "DevSecOps Pipeline Simulator — AppSec Hardening Lab" },
      {
        name: "description",
        content:
          "Run a simulated CI/CD pipeline: ruff lint, Bandit SAST, pip-audit SCA, pytest security regression tests and gated deploy.",
      },
      { property: "og:title", content: "DevSecOps CI/CD Pipeline Simulator" },
      {
        property: "og:description",
        content: "Watch lint, SAST, SCA, tests and deploy gates run against the hardened build.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Pipeline,
});

type Stage = { id: string; name: string; cmd: string; ms: number; out: Line[] };

const STAGES: Stage[] = [
  {
    id: "lint",
    name: "Lint & format",
    cmd: "ruff check . && black --check .",
    ms: 900,
    out: [
      { text: "$ ruff check .", tone: "cmd" },
      { text: "All checks passed!", tone: "ok" },
      { text: "$ black --check .  → 34 files unchanged", tone: "dim" },
    ],
  },
  {
    id: "sast",
    name: "SAST — Bandit",
    cmd: "bandit -r app/ -lll -f screen",
    ms: 1400,
    out: [
      { text: "$ bandit -r app/ -lll", tone: "cmd" },
      { text: "Run started: app/ (34 files, 2,188 LOC)", tone: "dim" },
      { text: "B602 subprocess_popen_with_shell_equals_true .... 0", tone: "ok" },
      { text: "B303 insecure_hash_function (MD5) ............... 0", tone: "ok" },
      { text: "B108 hardcoded_tmp_directory ................... 0", tone: "ok" },
      { text: "B110 try_except_pass ........................... 0", tone: "ok" },
      { text: "No issues identified.  (baseline: 6 high, 3 medium)", tone: "ok" },
    ],
  },
  {
    id: "sca",
    name: "SCA — pip-audit",
    cmd: "pip-audit --strict -r requirements.txt",
    ms: 1600,
    out: [
      { text: "$ pip-audit --strict -r requirements.txt", tone: "cmd" },
      { text: "Auditing 41 packages (pinned + hash verified)", tone: "dim" },
      { text: "Flask 3.0.3 ......... no known vulnerabilities", tone: "ok" },
      { text: "requests 2.32.3 ..... no known vulnerabilities", tone: "ok" },
      { text: "PyYAML 6.0.2 ........ no known vulnerabilities", tone: "ok" },
      { text: "Jinja2 3.1.4 ........ no known vulnerabilities", tone: "ok" },
      { text: "$ cyclonedx-py requirements -o sbom.json  → SBOM attached", tone: "ok" },
    ],
  },
  {
    id: "test",
    name: "Security regression tests",
    cmd: "example-security-regression-scenarios",
    ms: 1800,
    out: [
      { text: "$ example-security-regression-scenarios", tone: "cmd" },
      { text: "test_cmdi_rejects_metacharacters ............ PASSED", tone: "ok" },
      { text: "test_ping_uses_argv_not_shell ............... PASSED", tone: "ok" },
      { text: "test_upload_path_jail ....................... PASSED", tone: "ok" },
      { text: "test_upload_uuid_rename ..................... PASSED", tone: "ok" },
      { text: "test_password_hash_is_argon2id .............. PASSED", tone: "ok" },
      { text: "test_tempfile_mode_is_0600 .................. PASSED", tone: "ok" },
      { text: "test_auth_fails_closed_on_error ............. PASSED", tone: "ok" },
      { text: "Example security regression output: representative scenarios reviewed", tone: "ok" },
    ],
  },
  {
    id: "gate",
    name: "Security gate",
    cmd: "security-gate --require-review",
    ms: 700,
    out: [
      { text: "Example security gate: representative findings reviewed", tone: "ok" },
      { text: "Simulated gate decision: continue to release review", tone: "ok" },
    ],
  },
  {
    id: "release",
    name: "Build / release decision",
    cmd: "release-decision --require-all-gates",
    ms: 1100,
    out: [
      { text: "$ simulated-release-decision --require-all-gates", tone: "cmd" },
      { text: "representative gates: lint  sast  sca  regression review", tone: "ok" },
      {
        text: "SIMULATED PIPELINE RESULT — release decision requires real CI evidence",
        tone: "ok",
      },
    ],
  },
];

function Pipeline() {
  const [status, setStatus] = useState<Record<string, "idle" | "running" | "pass">>({});
  const [lines, setLines] = useState<Line[]>([{ text: "pipeline idle — press Run", tone: "dim" }]);
  const [running, setRunning] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const reset = () => {
    timers.current.forEach(clearTimeout);
    timers.current = [];
    setRunning(false);
    setStatus({});
    setLines([{ text: "pipeline idle — press Run", tone: "dim" }]);
  };

  const run = () => {
    reset();
    setRunning(true);
    setLines([
      { text: "$ simulated commit review → representative pipeline started", tone: "cmd" },
    ]);
    let t = 300;
    STAGES.forEach((s, idx) => {
      timers.current.push(
        setTimeout(() => {
          setStatus((p) => ({ ...p, [s.id]: "running" }));
          setLines((p) => [...p, { text: `── stage: ${s.name}`, tone: "warn" }]);
        }, t),
      );
      t += s.ms;
      timers.current.push(
        setTimeout(() => {
          setStatus((p) => ({ ...p, [s.id]: "pass" }));
          setLines((p) => [...p, ...s.out]);
          if (idx === STAGES.length - 1) setRunning(false);
        }, t),
      );
      t += 250;
    });
  };

  return (
    <div className="mx-auto max-w-7xl px-5 py-10">
      <h1 className="text-3xl font-bold">
        DevSecOps Security Pipeline <span className="text-primary">- Simulated</span>
      </h1>
      <p className="mt-2 max-w-2xl text-sm text-muted-foreground">
        Simulation only — these results are representative examples and are not produced by an
        actual Python CI workflow in this frontend.
      </p>
      <div className="mt-6 flex gap-3">
        <button
          onClick={run}
          disabled={running}
          className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          <Play className="size-4" /> {running ? "Running…" : "Run pipeline"}
        </button>
        <button
          onClick={reset}
          className="inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm hover:bg-secondary"
        >
          <RotateCcw className="size-4" /> Reset
        </button>
      </div>

      <div className="mt-8 grid gap-3 md:grid-cols-3 lg:grid-cols-6">
        {STAGES.map((s) => {
          const st = status[s.id] ?? "idle";
          return (
            <div
              key={s.id}
              className={`rounded-xl border p-4 transition-colors ${
                st === "pass"
                  ? "border-ok/50 bg-ok/10"
                  : st === "running"
                    ? "border-warn/50 bg-warn/10"
                    : "border-border bg-card/50"
              }`}
            >
              <div className="flex items-center gap-2">
                <span
                  className={`size-2 rounded-full ${
                    st === "pass"
                      ? "bg-ok"
                      : st === "running"
                        ? "animate-pulse bg-warn"
                        : "bg-muted-foreground/50"
                  }`}
                />
                <span className="text-sm font-semibold">{s.name}</span>
              </div>
              <div className="mt-2 font-mono text-[10px] break-all text-muted-foreground">
                {s.cmd}
              </div>
              <div className="mt-2 font-mono text-[10px] uppercase">
                {st === "pass" ? (
                  <span className="text-ok">passed</span>
                ) : st === "running" ? (
                  <span className="text-warn">running</span>
                ) : (
                  <span className="text-muted-foreground">queued</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="mt-6">
        <Terminal title="github-actions · security-ci" lines={lines} />
      </div>
    </div>
  );
}
