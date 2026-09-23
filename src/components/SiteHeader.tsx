import { Link } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";

const NAV = [
  { to: "/", label: "Dashboard" },
  { to: "/scanner", label: "Code Scanner" },
  { to: "/lab", label: "Exploit Lab" },
  { to: "/remediation", label: "Remediation" },
  { to: "/pipeline", label: "DevSecOps" },
  { to: "/report", label: "Report" },
] as const;

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/70 bg-background/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-x-6 gap-y-3 px-5 py-3">
        <Link to="/" className="flex items-center gap-2">
          <ShieldCheck className="size-5 text-primary" />
          <span className="font-mono text-sm font-bold tracking-tight">
            appsec<span className="text-primary">::</span>lab
          </span>
        </Link>
        <nav className="flex flex-wrap items-center gap-1 font-mono text-xs">
          {NAV.map((n) => (
            <Link
              key={n.to}
              to={n.to}
              activeOptions={{ exact: n.to === "/" }}
              className="rounded-md px-3 py-1.5 text-muted-foreground transition-colors hover:bg-secondary hover:text-foreground"
              activeProps={{ className: "bg-secondary text-primary" }}
            >
              {n.label}
            </Link>
          ))}
        </nav>
        <div className="ml-auto hidden items-center gap-2 font-mono text-[11px] text-muted-foreground sm:flex">
          <span className="size-2 animate-pulse rounded-full bg-ok" />
          posture: hardened
        </div>
      </div>
    </header>
  );
}
