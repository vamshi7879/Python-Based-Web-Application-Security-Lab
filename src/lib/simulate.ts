export type Line = { text: string; tone?: "cmd" | "ok" | "bad" | "warn" | "dim" };
export type SimResult = {
  lines: Line[];
  verdict: "exploited" | "blocked" | "safe" | "benign" | "exposed";
};

/* ------------------------------------------------------------------ utils */

const SHELL_META = /[;&|`$><\n()*?\\'"]/;

function sh(cmd: string): string {
  return cmd.trim().replace(/\s+/g, " ");
}

function randomHex(bytes: number): string {
  const values = new Uint8Array(bytes);
  globalThis.crypto.getRandomValues(values);
  return Array.from(values, (value) => value.toString(16).padStart(2, "0")).join("");
}

function humanTime(seconds: number): string {
  if (!isFinite(seconds)) return "heat death of the universe";
  if (seconds < 1e-3) return `${(seconds * 1e6).toFixed(0)} µs`;
  if (seconds < 1) return `${(seconds * 1e3).toFixed(1)} ms`;
  const units: [number, string][] = [
    [60, "seconds"],
    [60, "minutes"],
    [24, "hours"],
    [365, "days"],
    [1000, "years"],
    [1000, "thousand years"],
    [1000, "million years"],
    [1e9, "billion years"],
  ];
  let v = seconds;
  let label = "seconds";
  for (const [div, name] of units) {
    if (v < div) break;
    v = v / div;
    label = name;
  }
  if (label === "seconds") return `${v.toFixed(1)} seconds`;
  return `${v.toLocaleString(undefined, { maximumFractionDigits: 1 })} ${label}`;
}

function exhaustiveTime(candidates: number, guessesPerSecond: number): string {
  const hours = candidates / guessesPerSecond / 3600;
  if (hours < 1) return humanTime(candidates / guessesPerSecond);
  if (hours < 1000) return `${hours.toFixed(1)} hours (${(hours / 24).toFixed(1)} days)`;
  return humanTime(candidates / guessesPerSecond);
}

/* -------------------------------------------------- CWE-78 shell emulator */

const FAKE_FS: Record<string, string[]> = {
  "/etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "postgres:x:114:120:PostgreSQL admin:/var/lib/postgresql:/bin/bash",
    "appsvc:x:1001:1001::/home/appsvc:/bin/sh",
  ],
  "/etc/shadow": ["cat: /etc/shadow: Permission denied"],
  "/etc/hostname": ["appsec-prod-01"],
  "/etc/os-release": [
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"',
    'NAME="Debian GNU/Linux"',
    'VERSION_ID="12"',
  ],
  "/proc/version": [
    "Linux version 6.1.0-18-amd64 (debian-kernel@lists.debian.org) #1 SMP Debian 6.1.76-1",
  ],
  "/srv/app/.env": [
    "DATABASE_URL=postgresql://appsvc:S3cr3t@10.0.3.11:5432/appdb",
    "SECRET_KEY=1f3d9c6b0a7e4f2d",
    "AWS_ACCESS_KEY_ID=AKIA2X7QF3EXAMPLE",
  ],
};

function emulate(cmdline: string): Line[] {
  const line = sh(cmdline);
  if (!line) return [];
  const parts = line.split(" ");
  const bin = (parts[0] ?? "").replace(/^.*\//, "");
  const args = parts.slice(1);
  const out = (t: string, tone: Line["tone"] = "bad"): Line => ({ text: t, tone });

  switch (bin) {
    case "whoami":
      return [out("www-data")];
    case "id":
      return [out("uid=33(www-data) gid=33(www-data) groups=33(www-data)")];
    case "hostname":
      return [out("appsec-prod-01")];
    case "pwd":
      return [out("/srv/app")];
    case "uname": {
      if (args.includes("-a"))
        return [out("Linux appsec-prod-01 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64 GNU/Linux")];
      if (args.includes("-r")) return [out("6.1.0-18-amd64")];
      return [out("Linux")];
    }
    case "echo":
      return [out(args.join(" ").replace(/^["']|["']$/g, ""))];
    case "ls": {
      const long = args.some((a) => a.startsWith("-") && a.includes("l"));
      const target = args.find((a) => !a.startsWith("-")) ?? ".";
      const names = target.startsWith("/etc")
        ? ["passwd", "shadow", "hosts", "crontab", "ssl"]
        : ["app.py", "diagnostics.py", "requirements.txt", "uploads", ".env"];
      return long
        ? names.map((n) =>
            out(
              `-rw-r--r-- 1 www-data www-data ${String(1024 + n.length * 37).padStart(6)} Sep 21 03:14 ${n}`,
            ),
          )
        : [out(names.join("  "))];
    }
    case "cat": {
      const file = args.find((a) => !a.startsWith("-")) ?? "";
      const body = FAKE_FS[file];
      if (body) return body.map((l) => out(l));
      return [out(`cat: ${file || "-"}: No such file or directory`, "warn")];
    }
    case "env":
    case "printenv":
      return [
        out("PATH=/usr/local/sbin:/usr/local/bin:/usr/bin:/bin"),
        out("DATABASE_URL=postgresql://appsvc:S3cr3t@10.0.3.11:5432/appdb"),
        out("SECRET_KEY=1f3d9c6b0a7e4f2d"),
        out("AWS_ACCESS_KEY_ID=AKIA2X7QF3EXAMPLE"),
      ];
    case "ps":
      return [
        out("USER       PID %CPU %MEM COMMAND"),
        out("root         1  0.0  0.1 /sbin/init"),
        out("www-data   214  1.3  2.7 gunicorn: master [app:app]"),
        out("www-data   219  0.7  2.4 gunicorn: worker [app:app]"),
      ];
    case "netstat":
    case "ss":
      return [
        out("Proto Recv-Q Send-Q Local Address      Foreign Address    State"),
        out("tcp        0      0 0.0.0.0:8000       0.0.0.0:*          LISTEN"),
        out("tcp        0      0 10.0.3.11:5432     10.0.3.4:51422     ESTABLISHED"),
      ];
    case "ifconfig":
    case "ip":
      return [out("eth0: inet 10.0.3.4  netmask 255.255.255.0  broadcast 10.0.3.255")];
    case "curl":
    case "wget":
      return [
        out(`connecting to ${args.find((a) => !a.startsWith("-")) ?? "remote host"} ...`, "warn"),
        out("egress allowed — payload staged for C2 callback"),
      ];
    case "nc":
      return [out("reverse shell established to attacker listener")];
    case "rm":
      return [out(`removed ${args.filter((a) => !a.startsWith("-")).join(" ")}`)];
    case "sleep":
      return [out(`(blocked for ${args[0] ?? "0"}s — time-based blind injection oracle)`, "warn")];
    case "ping": {
      const host = args.find((a) => !a.startsWith("-")) ?? "";
      return [
        { text: `PING ${host} (${host}) 56(84) bytes of data.`, tone: "dim" },
        { text: `64 bytes from ${host}: icmp_seq=1 ttl=64 time=0.041 ms`, tone: "dim" },
      ];
    }
    default:
      return [out(`sh: 1: ${bin}: command not found`, "warn")];
  }
}

function splitChain(input: string): { op: string; cmd: string }[] {
  const segs: { op: string; cmd: string }[] = [];
  let buf = "";
  let op = "";
  for (let i = 0; i < input.length; i++) {
    const two = input.slice(i, i + 2);
    if (two === "&&" || two === "||") {
      segs.push({ op, cmd: buf });
      op = two;
      buf = "";
      i++;
      continue;
    }
    const c = input[i]!;
    if (c === ";" || c === "|" || c === "\n" || c === "&") {
      segs.push({ op, cmd: buf });
      op = c === "\n" ? ";" : c;
      buf = "";
      continue;
    }
    buf += c;
  }
  segs.push({ op, cmd: buf });
  return segs.filter((s) => s.cmd.trim().length > 0 || s.op);
}

function extractSubshells(input: string): string[] {
  const found: string[] = [];
  const dollar = /\$\(([^)]*)\)/g;
  const back = /`([^`]*)`/g;
  let m: RegExpExecArray | null;
  while ((m = dollar.exec(input))) found.push(m[1] ?? "");
  while ((m = back.exec(input))) found.push(m[1] ?? "");
  return found.filter((s) => s.trim());
}

function cmdi(input: string, hardened: boolean): SimResult {
  const raw = input;
  const subs = extractSubshells(raw);
  const chain = splitChain(raw.replace(/\$\([^)]*\)/g, "SUB").replace(/`[^`]*`/g, "SUB"));
  const injected = SHELL_META.test(raw);

  if (!hardened) {
    const lines: Line[] = [{ text: `$ sh -c "ping -c 1 ${raw}"     # shell=True`, tone: "cmd" }];
    // first segment is the ping itself
    const first = chain[0]?.cmd ?? raw;
    lines.push(...emulate(`ping ${first}`));

    for (const s of subs) {
      lines.push({ text: `$ ${sh(s)}   # command substitution executed first`, tone: "cmd" });
      lines.push(...emulate(s));
    }
    for (let i = 1; i < chain.length; i++) {
      const seg = chain[i]!;
      const label =
        seg.op === "|"
          ? "piped"
          : seg.op === "&&"
            ? "on success"
            : seg.op === "||"
              ? "on failure"
              : "chained";
      if (!seg.cmd.trim()) continue;
      lines.push({ text: `$ ${sh(seg.cmd)}   # ${label} via '${seg.op}'`, tone: "cmd" });
      lines.push(...emulate(seg.cmd));
    }

    if (injected || subs.length) {
      lines.push({
        text: `!! CWE-78 EXPLOITED — ${1 + subs.length + chain.length - 1} command(s) executed as www-data`,
        tone: "bad",
      });
      return { lines, verdict: "exploited" };
    }
    lines.push({
      text: "no metacharacters present — benign this time, still one payload away",
      tone: "warn",
    });
    return { lines, verdict: "benign" };
  }

  const lines: Line[] = [
    { text: `> validate_host(${JSON.stringify(raw)})`, tone: "cmd" },
    {
      text: `tokenizer: ${chain.length} segment(s), ${subs.length} substitution(s) detected`,
      tone: "dim",
    },
  ];
  const bad = Array.from(new Set(raw.split("").filter((c) => SHELL_META.test(c) || c === " ")));
  const valid = /^[a-zA-Z0-9.:-]{1,253}$/.test(raw.trim());

  if (!valid) {
    lines.push(
      {
        text: `character policy ^[a-zA-Z0-9.:-]{1,253}$ rejected: ${
          bad.length ? bad.map((c) => JSON.stringify(c)).join(" ") : "empty/oversized input"
        }`,
        tone: "warn",
      },
      { text: "ValueError: invalid host — shell interpreter never spawned", tone: "warn" },
      {
        text: `audit: {"event":"cmdi.blocked","cwe":"CWE-78","severity":"high","len":${raw.length}}`,
        tone: "dim",
      },
      { text: 'HTTP 400 Bad Request {"error":"Invalid host"}', tone: "ok" },
      { text: "OK BLOCKED — complete mediation at the trust boundary", tone: "ok" },
    );
    return { lines, verdict: "blocked" };
  }
  const host = raw.trim();
  lines.push(
    { text: "policy pass — no shell metacharacters, length within RFC 1035 limit", tone: "ok" },
    { text: `argv = ['/bin/ping', '-c', '1', '-w', '2', '--', '${host}']`, tone: "dim" },
    { text: "execve('/bin/ping', argv, env={'PATH':'/usr/bin'})  shell=False", tone: "dim" },
    { text: `64 bytes from ${host}: icmp_seq=1 ttl=64 time=0.041 ms`, tone: "dim" },
    { text: "OK executed safely — argument vectorization, 5s timeout, no interpreter", tone: "ok" },
  );
  return { lines, verdict: "safe" };
}

/* ----------------------------------------------------------- CWE-22 paths */

function decodePath(input: string): { decoded: string; notes: string[] } {
  const notes: string[] = [];
  let s = input;
  for (let i = 0; i < 3; i++) {
    const next = s.replace(/%[0-9a-f]{2}/gi, (m) => {
      try {
        return decodeURIComponent(m);
      } catch {
        return m;
      }
    });
    if (next === s) break;
    notes.push(`URL-decode pass ${i + 1}: ${s} -> ${next}`);
    s = next;
  }
  if (s.includes("\0") || /%00/i.test(input)) {
    notes.push("null byte detected — truncation attack attempt");
    s = s.replace(/\0/g, "");
  }
  if (s.includes("\\")) {
    notes.push("backslash separators normalised to '/'");
    s = s.replace(/\\/g, "/");
  }
  return { decoded: s, notes };
}

function resolvePath(base: string, rel: string): string {
  const abs = rel.startsWith("/");
  const segs = (abs ? rel : `${base}/${rel}`).split("/");
  const stack: string[] = [];
  for (const seg of segs) {
    if (!seg || seg === ".") continue;
    if (seg === "..") stack.pop();
    else stack.push(seg);
  }
  return "/" + stack.join("/");
}

const UPLOAD_DIR = "/srv/app/uploads";
const ALLOWED_EXT = [".pdf", ".png", ".jpg", ".jpeg", ".txt", ".csv"];

function pathTrav(input: string, hardened: boolean): SimResult {
  const { decoded, notes } = decodePath(input.trim());
  const resolved = resolvePath(UPLOAD_DIR, decoded);
  const escapes = !(resolved + "/").startsWith(UPLOAD_DIR + "/");
  const extMatch = resolved.match(/\.[a-z0-9]+$/i);
  const ext = (extMatch ? extMatch[0] : "").toLowerCase();
  const allowed = ALLOWED_EXT.includes(ext);
  const upCount = (decoded.match(/\.\.\//g) ?? []).length;

  if (!hardened) {
    const lines: Line[] = [
      { text: `$ open(os.path.join("${UPLOAD_DIR}", "${input}"), "wb")`, tone: "cmd" },
      ...notes.map((n): Line => ({ text: n, tone: "warn" })),
      {
        text: `traversal segments: ${upCount} · absolute path: ${decoded.startsWith("/")}`,
        tone: "dim",
      },
      { text: `resolved -> ${resolved}`, tone: escapes ? "bad" : "dim" },
    ];
    if (escapes) {
      const leak = FAKE_FS[resolved];
      lines.push({
        text: `wrote ${1024 + resolved.length * 13} bytes outside the upload jail`,
        tone: "bad",
      });
      if (leak) lines.push(...leak.map((l): Line => ({ text: l, tone: "bad" })));
      lines.push({
        text: "!! CWE-22 EXPLOITED — directory escape, arbitrary file write",
        tone: "bad",
      });
      return { lines, verdict: "exploited" };
    }
    if (!allowed) {
      lines.push(
        {
          text: `!! stored executable/unknown extension '${ext || "none"}' — reachable at /uploads/${decoded}`,
          tone: "bad",
        },
        { text: "!! CWE-434 chain — web shell upload possible", tone: "bad" },
      );
      return { lines, verdict: "exploited" };
    }
    lines.push({
      text: "stored (client filename preserved — still fingerprintable)",
      tone: "warn",
    });
    return { lines, verdict: "benign" };
  }

  const lines: Line[] = [
    { text: `> save_upload(${JSON.stringify(input)}, data)`, tone: "cmd" },
    ...notes.map((n): Line => ({ text: n, tone: "dim" })),
    { text: `basename() -> ${decoded.split("/").pop() || "(empty)"}`, tone: "dim" },
    { text: `Path.resolve() -> ${resolved}`, tone: "dim" },
    {
      text: `target.is_relative_to("${UPLOAD_DIR}") -> ${!escapes}`,
      tone: escapes ? "warn" : "ok",
    },
  ];
  if (escapes) {
    lines.push(
      { text: "PermissionError: path escapes upload jail — request refused", tone: "warn" },
      { text: 'audit: {"event":"path.traversal.blocked","cwe":"CWE-22"}', tone: "dim" },
      { text: "OK BLOCKED — canonicalisation + jail check", tone: "ok" },
    );
    return { lines, verdict: "blocked" };
  }
  if (!allowed) {
    lines.push(
      { text: `extension '${ext || "none"}' not in {${ALLOWED_EXT.join(",")}}`, tone: "warn" },
      { text: "ValueError: rejected upload", tone: "warn" },
      { text: "OK BLOCKED — allow-list refused the file type", tone: "ok" },
    );
    return { lines, verdict: "blocked" };
  }
  const uuid = pseudoUuid(input);
  lines.push(
    { text: `uuid4() -> ${uuid}`, tone: "dim" },
    { text: `stored ${UPLOAD_DIR}/${uuid}${ext}  mode 0600  (client name discarded)`, tone: "ok" },
    {
      text: "served via Content-Disposition: attachment, X-Content-Type-Options: nosniff",
      tone: "ok",
    },
    { text: "OK CWE-22 REMEDIATED — jailed, renamed, non-executable", tone: "ok" },
  );
  return { lines, verdict: "safe" };
}

function pseudoUuid(seed: string): string {
  let h = 0x811c9dc5;
  const hex: string[] = [];
  for (let i = 0; i < 32; i++) {
    h = (h ^ (seed.charCodeAt(i % Math.max(seed.length, 1)) || 7 + i)) >>> 0;
    h = (h * 16777619) >>> 0;
    hex.push(((h >>> (i % 8)) % 16).toString(16));
  }
  const s = hex.join("");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-4${s.slice(13, 16)}-a${s.slice(17, 20)}-${s.slice(20, 32)}`;
}

/* ------------------------------------------------------ CWE-312 passwords */

function shannon(s: string): number {
  if (!s) return 0;
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] ?? 0) + 1;
  return -Object.values(freq).reduce((acc, n) => {
    const p = n / s.length;
    return acc + p * Math.log2(p);
  }, 0);
}

function charsetSize(s: string): { size: number; sets: string[] } {
  const sets: string[] = [];
  let size = 0;
  if (/[a-z]/.test(s)) {
    sets.push("lower a-z");
    size += 26;
  }
  if (/[A-Z]/.test(s)) {
    sets.push("upper A-Z");
    size += 26;
  }
  if (/[0-9]/.test(s)) {
    sets.push("digits 0-9");
    size += 10;
  }
  if (/[^a-zA-Z0-9]/.test(s)) {
    sets.push("symbols");
    size += 33;
  }
  return { size: Math.max(size, 1), sets };
}

const COMMON = new Set([
  "password",
  "123456",
  "123456789",
  "qwerty",
  "hunter2",
  "letmein",
  "admin",
  "welcome",
  "monkey",
  "dragon",
  "iloveyou",
  "abc123",
  "football",
  "password1",
]);

async function creds(input: string, hardened: boolean): Promise<SimResult> {
  const pw = input;
  if (!pw) {
    return {
      verdict: "blocked",
      lines: [{ text: "> enter a password to analyse", tone: "warn" }],
    };
  }
  const { size, sets } = charsetSize(pw);
  const nistBits = pw.length * Math.log2(size);
  const entropyPerChar = shannon(pw);
  const keyspace = Math.pow(size, pw.length);
  const common = COMMON.has(pw.toLowerCase());
  const gpu = 150e9; // 150 GH/s SHA-256 on 8x RTX 4090
  const cpu = 25e6; // 25 MH/s single CPU core
  const argon = 120e3; // 120 kH/s Argon2id m=64MiB
  const averageCandidates = keyspace / 2;

  if (!hardened) {
    const lines: Line[] = [
      { text: `INSERT INTO users (email, password) VALUES (?, '${pw}')`, tone: "cmd" },
      { text: `stored cleartext value      : '${pw}'`, tone: "bad" },
      {
        text: "database disclosure reveals the original password immediately — no cracking required",
        tone: "bad",
      },
      {
        text: `charset: ${sets.join(", ") || "none"} (N=${size}) · length ${pw.length}`,
        tone: "dim",
      },
      {
        text: `NIST entropy: ${nistBits.toFixed(1)} bits · Shannon: ${entropyPerChar.toFixed(2)} bits/char`,
        tone: "dim",
      },
      { text: `keyspace: ${keyspace.toExponential(2)} candidates`, tone: "dim" },
      {
        text: `CPU exhaustive average (25 MH/s)      : ${humanTime(averageCandidates / cpu)}`,
        tone: "warn",
      },
      {
        text: `GPU exhaustive average (150 GH/s): ${humanTime(averageCandidates / gpu)}`,
        tone: "bad",
      },
      {
        text: common
          ? "breach corpus / dictionary lookup: HIT — separate from exhaustive search"
          : "breach corpus / dictionary lookup: MISS — separate from exhaustive search",
        tone: "bad",
      },
      { text: "!! CWE-312 EXPLOITED — one DB read equals total account takeover", tone: "bad" },
    ];
    return { lines, verdict: "exploited" };
  }

  const salt = randomHex(16);
  const simulatedHash = randomHex(32);
  const lines: Line[] = [
    {
      text: "ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4, salt_len=16)",
      tone: "cmd",
    },
    { text: `$argon2id$v=19$m=65536,t=3,p=4$${salt}$${simulatedHash}`, tone: "ok" },
    {
      text: "simulation: encoded Argon2id record shown with a fresh 128-bit browser CSPRNG salt",
      tone: "dim",
    },
    { text: "work factor: 64 MiB x 3 passes x 4 lanes ≈ 41 ms/verify", tone: "dim" },
    {
      text: `NIST entropy of this secret: ${nistBits.toFixed(1)} bits (${
        nistBits < 40 ? "weak" : nistBits < 60 ? "moderate" : "strong"
      })`,
      tone: nistBits < 40 ? "warn" : "ok",
    },
    {
      text: `attacker throughput collapses 150 GH/s -> 120 kH/s (${(gpu / argon).toExponential(1)}x slower)`,
      tone: "ok",
    },
    {
      text: `exhaustive search @ 120 kH/s — worst: ${exhaustiveTime(keyspace, argon)} · average: ${exhaustiveTime(averageCandidates, argon)}`,
      tone: "ok",
    },
    ...(common
      ? [
          {
            text: "breach-corpus check: HIT — registration refused independently of exhaustive-search time",
            tone: "warn" as const,
          },
        ]
      : []),
    { text: "verify(): constant time · check_needs_rehash(): auto-upgrade on login", tone: "ok" },
    { text: "OK CWE-312 REMEDIATED — unique salt + memory-hard password hashing", tone: "ok" },
  ];
  return { lines, verdict: common ? "blocked" : "safe" };
}

/* ------------------------------------------------------- CWE-377 tmpfiles */

function tmp(input: string, hardened: boolean): SimResult {
  const userId = input.trim() || "123";
  const name = `user_${userId}.tmp`;
  const looksAbsolute = name.startsWith("/");
  const full = looksAbsolute ? name : `/tmp/${name}`;
  const digits = (name.match(/\d+/g) ?? []).join("");
  const hasPid = /pid|\bos\.getpid|\d{3,6}/i.test(name);
  const hasTime = /time|ts|\d{10}/i.test(name);
  const randomish =
    /[a-z0-9]{8,}/i.test(name.replace(/\d+/g, "")) && !/user|tmp|export|job/i.test(name);
  const variableBits = digits ? Math.log2(Math.pow(10, digits.length)) : randomish ? 48 : 0;
  const guesses = Math.pow(2, variableBits);

  if (!hardened) {
    const lines: Line[] = [
      { text: `$ open("${full}", "w")   # mode inherited from umask 022`, tone: "cmd" },
      { text: `-rw-r--r-- 1 www-data www-data  ${full}`, tone: "bad" },
      {
        text: `name entropy: ${variableBits.toFixed(1)} bits (~${guesses.toExponential(1)} guesses)`,
        tone: variableBits > 40 ? "warn" : "bad",
      },
      {
        text: hasPid
          ? "predictor: numeric/PID component — PID space is 32768, brute-forceable in ms"
          : "predictor: fully static component — attacker pre-creates the path",
        tone: "bad",
      },
      ...(hasTime
        ? [
            {
              text: "predictor: timestamp component — second-resolution guessable",
              tone: "bad" as const,
            },
          ]
        : []),
      { text: `attacker: ln -s /etc/crontab ${full}`, tone: "bad" },
      { text: "TOCTOU: stat() ... open() race window won by attacker", tone: "bad" },
      { text: "export payload written through the symlink into /etc/crontab", tone: "bad" },
      { text: "world-readable PII exposed to every local user (mode 0644)", tone: "bad" },
      {
        text: "!! CWE-377 EXPLOITED — arbitrary file overwrite + information disclosure",
        tone: "bad",
      },
    ];
    return { lines, verdict: "exploited" };
  }

  const safeSlug = userId.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 16) || "job";
  const rnd = pseudoUuid(name).replace(/-/g, "").slice(0, 16);
  const lines: Line[] = [
    {
      text: `with tempfile.NamedTemporaryFile(dir=SPOOL, prefix="${safeSlug}-", delete=True) as fh:`,
      tone: "cmd",
    },
    { text: `created /var/spool/app/appsec-7f21/${safeSlug}-${rnd}.tmp`, tone: "ok" },
    { text: "simulated server-generated filename — randomness is not measured here", tone: "ok" },
    { text: "flags: O_CREAT|O_EXCL|O_RDWR  (atomic create — no TOCTOU window)", tone: "ok" },
    { text: "-rw------- 1 appsvc appsvc   mode 0600, spool dir 0700, sticky", tone: "ok" },
    { text: "symlink attack: open() returns EEXIST, job aborts and alerts", tone: "ok" },
    { text: "context manager unlinks on exit, including on exception paths", tone: "ok" },
    {
      text: "OK CWE-377 REMEDIATED — unpredictable, atomic, least-privilege, cleaned up",
      tone: "ok",
    },
  ];
  return { lines, verdict: "safe" };
}

/* ------------------------------------------------- CWE-396 error handling */

type ExcInfo = { cls: string; base: string; note: string };

function classifyException(input: string): ExcInfo {
  const s = input.trim();
  const lower = s.toLowerCase();
  const named = s.match(/[A-Z][A-Za-z]*(Error|Exit|Interrupt|Exception|Warning)/)?.[0];
  const table: Record<string, ExcInfo> = {
    SystemExit: {
      cls: "SystemExit",
      base: "BaseException",
      note: "process shutdown signal swallowed — worker never exits",
    },
    KeyboardInterrupt: {
      cls: "KeyboardInterrupt",
      base: "BaseException",
      note: "Ctrl-C swallowed — operator loses control of the process",
    },
    MemoryError: {
      cls: "MemoryError",
      base: "Exception",
      note: "OOM condition hidden — undefined behaviour downstream",
    },
    OperationalError: {
      cls: "psycopg2.OperationalError",
      base: "Exception",
      note: "database unreachable — requests silently return stale/empty data",
    },
    ZeroDivisionError: {
      cls: "ZeroDivisionError",
      base: "ArithmeticError",
      note: "logic bug masked — corrupt computation continues",
    },
    TimeoutError: {
      cls: "TimeoutError",
      base: "OSError",
      note: "upstream timeout hidden — cascading failure",
    },
    PermissionError: {
      cls: "PermissionError",
      base: "OSError",
      note: "authz failure treated as success",
    },
    InvalidSignature: {
      cls: "cryptography.exceptions.InvalidSignature",
      base: "Exception",
      note: "signature verification failure ignored — forged tokens accepted",
    },
  };
  if (named && table[named]) return table[named]!;
  if (named)
    return {
      cls: named,
      base: named.endsWith("Error") ? "Exception" : "BaseException",
      note: "unclassified failure swallowed by the bare handler",
    };
  if (/signature|token|auth/.test(lower))
    return {
      cls: "AuthenticationError",
      base: "Exception",
      note: "authentication failure reported as success",
    };
  if (/database|db|connect/.test(lower)) return table["OperationalError"]!;
  if (/timeout/.test(lower)) return table["TimeoutError"]!;
  if (/permission|denied|forbidden/.test(lower)) return table["PermissionError"]!;
  return {
    cls: "RuntimeError",
    base: "Exception",
    note: "unclassified failure swallowed by the bare handler",
  };
}

function exceptSim(input: string, hardened: boolean): SimResult {
  const cause = input.trim() || "signature mismatch";
  const info = classifyException(cause);
  const isBase = info.base === "BaseException";
  const corr = pseudoUuid(cause).slice(0, 8);

  if (!hardened) {
    const lines: Line[] = [
      { text: `> authenticate(token)  # fault injected: ${cause}`, tone: "cmd" },
      { text: `raise ${info.cls}(${JSON.stringify(cause)})`, tone: "dim" },
      { text: "try: ... except:  pass      # bare except catches BaseException", tone: "bad" },
      {
        text: isBase
          ? `caught ${info.cls} — a BaseException that MUST propagate; ${info.note}`
          : `caught ${info.cls} (${info.base}) — ${info.note}`,
        tone: "bad",
      },
      { text: 'return {"ok": true, "user": "guest"}   <- control FAILS OPEN', tone: "bad" },
      { text: "audit log: (empty)   SIEM detection: none", tone: "bad" },
      ...(isBase
        ? [
            {
              text: "container health check still green while the worker is wedged",
              tone: "bad" as const,
            },
          ]
        : []),
      { text: "!! CWE-396 EXPLOITED — security control failure reported as success", tone: "bad" },
    ];
    return { lines, verdict: "exploited" };
  }

  const lines: Line[] = [
    { text: `> authenticate(token)  # fault injected: ${cause}`, tone: "cmd" },
    {
      text: `except ${info.base === "BaseException" ? info.cls + " : raise  # never swallowed" : info.cls + " as exc:"}`,
      tone: "dim",
    },
    ...(isBase
      ? [
          {
            text: `${info.cls} re-raised — shutdown/interrupt semantics preserved`,
            tone: "ok" as const,
          },
          {
            text: "graceful drain: in-flight requests finished, worker exits 0",
            tone: "ok" as const,
          },
        ]
      : [
          {
            text: `log.error auth.failure {"corr":"${corr}","exc":"${info.cls}","cause":"${cause}","ip":"203.0.113.9"}`,
            tone: "ok" as const,
          },
          {
            text: `client: {"ok": false, "error": "Authentication failed", "corr": "${corr}"}  HTTP 401`,
            tone: "ok" as const,
          },
          {
            text: "no stack trace, no driver string, no internal path leaked to caller",
            tone: "dim" as const,
          },
          {
            text: "SIEM rule AUTH-05 incremented — alert at 5 failures / 60s / source IP",
            tone: "ok" as const,
          },
        ]),
    { text: "OK CWE-396 REMEDIATED — fails closed, typed, observable", tone: "ok" },
  ];
  return { lines, verdict: "blocked" };
}

/* -------------------------------------------------------- CWE-1395 deps */

type Advisory = {
  cve: string;
  cvss: number;
  vector: string;
  affected: string;
  fixed: string;
  note: string;
  cwe: string;
};

const ADVISORIES: Record<string, Advisory[]> = {
  flask: [
    {
      cve: "CVE-2018-1000656",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H",
      affected: "<0.12.3",
      fixed: "0.12.3",
      note: "Denial of service through crafted JSON data when the affected JSON parsing path is reachable",
      cwe: "CWE-20",
    },
    {
      cve: "CVE-2023-30861",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:H/I:N/A:N",
      affected: "<2.2.5",
      fixed: "2.2.5",
      note: "Session cookie cached by proxies — session disclosure",
      cwe: "CWE-539",
    },
  ],
  requests: [
    {
      cve: "CVE-2018-18074",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      affected: "<2.20.0",
      fixed: "2.20.0",
      note: "Authorization header leaked on HTTPS->HTTP redirect",
      cwe: "CWE-200",
    },
    {
      cve: "CVE-2023-32681",
      cvss: 6.1,
      vector: "AV:N/AC:L/PR:N/UI:R/C:H/I:N/A:N",
      affected: "<2.31.0",
      fixed: "2.31.0",
      note: "Proxy-Authorization leaked to destination server",
      cwe: "CWE-200",
    },
  ],
  pyyaml: [
    {
      cve: "CVE-2020-1747",
      cvss: 9.8,
      vector: "AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
      affected: "<5.3.1",
      fixed: "5.3.1",
      note: "full_load / FullLoader arbitrary code execution",
      cwe: "CWE-20",
    },
    {
      cve: "CVE-2020-14343",
      cvss: 9.8,
      vector: "AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
      affected: "<5.4",
      fixed: "5.4",
      note: "Incomplete fix for CVE-2020-1747 — RCE via python/object/new",
      cwe: "CWE-502",
    },
  ],
  jinja2: [
    {
      cve: "CVE-2019-10906",
      cvss: 8.6,
      vector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
      affected: "<2.10.1",
      fixed: "2.10.1",
      note: "str.format_map sandbox escape",
      cwe: "CWE-134",
    },
    {
      cve: "CVE-2024-22195",
      cvss: 5.4,
      vector: "AV:N/AC:L/PR:L/UI:R/C:L/I:L/A:N",
      affected: "<3.1.3",
      fixed: "3.1.3",
      note: "XSS via xmlattr filter keys",
      cwe: "CWE-79",
    },
  ],
  pillow: [
    {
      cve: "CVE-2021-25287",
      cvss: 9.1,
      vector: "AV:N/AC:L/PR:N/UI:N/C:H/I:N/A:H",
      affected: "<8.2.0",
      fixed: "8.2.0",
      note: "Out-of-bounds read in J2K decoder",
      cwe: "CWE-125",
    },
    {
      cve: "CVE-2023-4863",
      cvss: 8.8,
      vector: "AV:N/AC:L/PR:N/UI:R/C:H/I:H/A:H",
      affected: "<10.0.1",
      fixed: "10.0.1",
      note: "libwebp heap buffer overflow",
      cwe: "CWE-787",
    },
  ],
  urllib3: [
    {
      cve: "CVE-2021-33503",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H",
      affected: "<1.26.5",
      fixed: "1.26.5",
      note: "ReDoS via crafted URL authority",
      cwe: "CWE-400",
    },
    {
      cve: "CVE-2023-43804",
      cvss: 8.1,
      vector: "AV:N/AC:H/PR:N/UI:N/C:H/I:H/A:N",
      affected: "<1.26.17",
      fixed: "1.26.17",
      note: "Cookie header leaked on cross-origin redirect",
      cwe: "CWE-200",
    },
  ],
  cryptography: [
    {
      cve: "CVE-2023-23931",
      cvss: 6.5,
      vector: "AV:N/AC:L/PR:L/UI:N/C:N/I:H/A:N",
      affected: "<39.0.1",
      fixed: "39.0.1",
      note: "Cipher.update_into buffer overflow on immutable buffers",
      cwe: "CWE-787",
    },
    {
      cve: "CVE-2023-49083",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H",
      affected: "<41.0.6",
      fixed: "41.0.6",
      note: "NULL dereference loading PKCS7 certificates",
      cwe: "CWE-476",
    },
  ],
  django: [
    {
      cve: "CVE-2022-28346",
      cvss: 9.8,
      vector: "AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H",
      affected: "<3.2.13",
      fixed: "3.2.13",
      note: "SQL injection via QuerySet.annotate column aliases",
      cwe: "CWE-89",
    },
    {
      cve: "CVE-2024-27351",
      cvss: 5.3,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:L",
      affected: "<4.2.11",
      fixed: "4.2.11",
      note: "ReDoS in Truncator.words",
      cwe: "CWE-1333",
    },
  ],
  werkzeug: [
    {
      cve: "CVE-2023-25577",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H",
      affected: "<2.2.3",
      fixed: "2.2.3",
      note: "Multipart parser resource exhaustion",
      cwe: "CWE-400",
    },
    {
      cve: "CVE-2024-34069",
      cvss: 7.5,
      vector: "AV:N/AC:H/PR:N/UI:R/C:H/I:H/A:H",
      affected: "<3.0.3",
      fixed: "3.0.3",
      note: "Debugger PIN bypass allows RCE",
      cwe: "CWE-1188",
    },
  ],
  paramiko: [
    {
      cve: "CVE-2023-48795",
      cvss: 5.9,
      vector: "AV:N/AC:H/PR:N/UI:N/C:H/I:H/A:N",
      affected: "<3.4.0",
      fixed: "3.4.0",
      note: "Terrapin SSH prefix truncation attack",
      cwe: "CWE-222",
    },
  ],
  numpy: [
    {
      cve: "CVE-2021-33430",
      cvss: 5.3,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:L",
      affected: "<1.22.0",
      fixed: "1.22.0",
      note: "Buffer overflow in numpy.pad",
      cwe: "CWE-119",
    },
  ],
  lxml: [
    {
      cve: "CVE-2022-2309",
      cvss: 7.5,
      vector: "AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:H",
      affected: "<4.9.1",
      fixed: "4.9.1",
      note: "NULL dereference in iterwalk",
      cwe: "CWE-476",
    },
  ],
};

function parsePkg(entry: string): { name: string; version: string; op: string } {
  const m = entry.trim().match(/^([A-Za-z0-9._-]+)\s*(==|>=|<=|~=|>|<)?\s*([0-9][0-9A-Za-z._-]*)?/);
  return {
    name: (m?.[1] ?? entry.trim()).toLowerCase().replace(/_/g, "-"),
    op: m?.[2] ?? "",
    version: m?.[3] ?? "",
  };
}

function cmpVersion(a: string, b: string): number {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

function severityOf(cvss: number): string {
  return cvss >= 9 ? "CRITICAL" : cvss >= 7 ? "HIGH" : cvss >= 4 ? "MEDIUM" : "LOW";
}

function deps(input: string, hardened: boolean): SimResult {
  const entries = input
    .split(/[\n,]/)
    .map((e) => e.trim())
    .filter(Boolean);
  const list = entries.length ? entries : ["flask==0.12.2"];

  type Hit = { entry: string; name: string; version: string; adv: Advisory };
  const hits: Hit[] = [];
  const unknown: string[] = [];
  const clean: string[] = [];

  for (const entry of list) {
    const { name, version } = parsePkg(entry);
    const advs = ADVISORIES[name];
    if (!advs) {
      unknown.push(entry);
      continue;
    }
    if (!version) {
      advs.forEach((adv) => hits.push({ entry, name, version: "(unpinned)", adv }));
      continue;
    }
    const matched = advs.filter((a) => cmpVersion(version, a.fixed) < 0);
    if (matched.length) matched.forEach((adv) => hits.push({ entry, name, version, adv }));
    else clean.push(`${name}==${version}`);
  }

  if (!hardened) {
    const lines: Line[] = [
      { text: "$ pip install -r requirements.txt     # no SCA gate in the pipeline", tone: "cmd" },
      ...list.map((e): Line => ({ text: `  Collecting ${e}`, tone: "dim" })),
      { text: `  Successfully installed ${list.length} package(s)`, tone: "dim" },
    ];
    for (const h of hits)
      lines.push(
        {
          text: `${h.adv.cve}  ${severityOf(h.adv.cvss)} ${h.adv.cvss.toFixed(1)}  ${h.name} ${h.version}`,
          tone: "bad",
        },
        { text: `   ${h.adv.note}  (${h.adv.cwe})`, tone: "bad" },
        { text: `   affected ${h.adv.affected} · CVSS:3.1/${h.adv.vector}`, tone: "dim" },
        {
          text: "   reachability note: a version match indicates exposure; exploitability depends on affected code paths and configuration",
          tone: "warn",
        },
      );
    for (const u of unknown)
      lines.push({
        text: `${u}: no advisory data — unverified, no SBOM, no provenance`,
        tone: "warn",
      });
    if (hits.length) {
      lines.push({
        text: `!! CWE-1395 EXPOSED — ${hits.length} known-vulnerable component(s); exploitability depends on reachable features and configuration`,
        tone: "bad",
      });
      return { lines, verdict: "exposed" };
    }
    lines.push({ text: "no advisory matched — but nothing verified this build", tone: "warn" });
    return { lines, verdict: "benign" };
  }

  const lines: Line[] = [
    { text: "$ pip-audit --strict --require-hashes -r requirements.txt", tone: "cmd" },
  ];
  if (hits.length) {
    lines.push({ text: "Name        Version   ID                 Fix Versions", tone: "dim" });
    for (const h of hits)
      lines.push({
        text: `${h.name.padEnd(12)}${h.version.padEnd(10)}${h.adv.cve.padEnd(19)}${h.adv.fixed}`,
        tone: "warn",
      });
    const worst = Math.max(...hits.map((h) => h.adv.cvss));
    lines.push(
      {
        text: `highest severity: ${severityOf(worst)} ${worst.toFixed(1)} — exceeds gate threshold 7.0`,
        tone: "warn",
      },
      { text: "exit code 1 — pipeline FAILED, artifact not published", tone: "ok" },
      ...hits.map((h): Line => ({
        text: `auto-PR: bump ${h.name} -> ${h.adv.fixed} (+ hash refresh)`,
        tone: "ok",
      })),
      {
        text: "OK CWE-1395 ADDRESSED IN SIMULATION — review required before a real release",
        tone: "ok",
      },
    );
    return { lines, verdict: "blocked" };
  }
  lines.push(
    ...clean.map((c): Line => ({ text: `  ${c}  no known vulnerabilities`, tone: "ok" })),
    ...unknown.map((u): Line => ({
      text: `  ${u}  not in advisory DB — pinned + hash-locked, SBOM records it`,
      tone: "dim",
    })),
    {
      text: "cyclonedx-py requirements -o sbom.json  (SBOM signed and attached to the release)",
      tone: "ok",
    },
    { text: "dependabot + weekly pip-audit cron enabled", tone: "ok" },
    { text: "exit code 0 — build promoted", tone: "ok" },
  );
  return { lines, verdict: "safe" };
}

/* ------------------------------------------------------------ dispatcher */

export async function simulate(id: string, input: string, hardened: boolean): Promise<SimResult> {
  switch (id) {
    case "cmdi":
      return cmdi(input, hardened);
    case "path":
      return pathTrav(input, hardened);
    case "creds":
      return creds(input, hardened);
    case "tmp":
      return tmp(input, hardened);
    case "except":
      return exceptSim(input, hardened);
    case "deps":
      return deps(input, hardened);
    default:
      return { lines: [{ text: "unknown module" }], verdict: "safe" };
  }
}
