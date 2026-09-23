export type Severity = "Critical" | "High" | "Medium" | "Low";

export type Vuln = {
  id: string;
  priority: number;
  cwe: string;
  title: string;
  short: string;
  severity: Severity;
  likelihood: string;
  impactRating: string;
  overallRisk: string;
  reason: string;
  weakness: string;
  danger: string;
  scenario: string;
  cvss?: number;
  vector?: string;
  owasp: string;
  mitre: string;
  file: string;
  summary: string;
  impact: string[];
  fix: string[];
  principles: string[];
  before: string;
  after: string;
  remediation: string;
  validation: string;
  simulationNotice?: string;
  samplePayloads: string[];
  inputLabel: string;
};

const common = {
  cmdi: {
    id: "cmdi",
    priority: 1,
    cwe: "CWE-78",
    title: "OS Command Injection",
    short: "Command Injection",
    severity: "Critical" as Severity,
    likelihood: "High",
    impactRating: "Critical",
    overallRisk: "Critical",
    reason: "Potential command execution and system compromise",
    weakness: "User-controlled input is directly incorporated into an operating-system command.",
    danger:
      "An attacker-controlled value can alter the intended command and execute additional commands with the service account's permissions.",
    scenario:
      "The host field is submitted as `127.0.0.1; whoami`; vulnerable string construction passes the extra command to a shell.",
    cvss: 9.8,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    owasp: "A03:2021 - Injection",
    mitre: "Contextual ATT&CK relationship: T1059 - Command and Scripting Interpreter",
    file: "app/diagnostics.py",
    summary: "A diagnostics function builds a shell command from user input without validation.",
    impact: [
      "Possible command execution as the service account",
      "Potential access to application secrets",
      "Possible compromise of the host or connected services",
    ],
    fix: [
      "Strictly validate a hostname or IP address",
      "Pass an argument list to subprocess.run",
      "Use shell=False, check=True, a timeout, and least privilege",
    ],
    principles: [
      "Complete Mediation",
      "Least Privilege",
      "Economy of Mechanism",
      "Defense in Depth",
    ],
    before: `cmd = "ping -c 1 " + host
os.popen(cmd).read()`,
    after: `import subprocess

subprocess.run(
    ["ping", "-c", "1", validated_host],
    shell=False,
    check=True
)`,
    remediation:
      "Validate the host at the trust boundary and use argument vectorization so no shell interprets the value.",
    validation:
      "The browser compares representative benign and malicious inputs; it never starts an operating-system process.",
    simulationNotice: "Educational simulation - no operating-system commands are executed.",
    samplePayloads: ["127.0.0.1", "127.0.0.1; whoami", "| cat /etc/passwd", "8.8.8.8 && id"],
    inputLabel: "Website or host field",
  },
  path: {
    id: "path",
    priority: 2,
    cwe: "CWE-22",
    title: "Path Traversal in File Handling",
    short: "Path Traversal",
    severity: "High" as Severity,
    likelihood: "High",
    impactRating: "High",
    overallRisk: "High",
    reason: "Unauthorized file access depending on permissions",
    weakness:
      "User-supplied file paths are accessed without sufficient validation and containment.",
    danger:
      "Traversal sequences such as `../` can escape the intended directory if canonical containment is not enforced.",
    scenario:
      "The filename input represents `../../sensitive.txt`; a vulnerable join may resolve outside `/uploads`.",
    cvss: 8.1,
    vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    owasp: "A01:2021 - Broken Access Control",
    mitre: "Contextual ATT&CK relationship: T1083 - File and Directory Discovery",
    file: "app/uploads.py",
    summary:
      "A file path is accepted from the user without canonicalization and base-directory containment.",
    impact: [
      "Unauthorized reads or writes where permissions allow",
      "Possible overwrite of application files",
      "Extension and size controls may be bypassed",
    ],
    fix: [
      "Canonicalize and restrict paths to the base directory",
      "Use server-generated filenames",
      "Validate extensions, size, content, and access control",
    ],
    principles: ["Complete Mediation", "Fail-Safe Defaults", "Defense in Depth"],
    before: `path = os.path.join("/uploads", user_filename)
with open(path, "rb") as f:
    data = f.read()`,
    after: `from pathlib import Path

BASE_DIR = Path("/srv/app/uploads").resolve()
candidate = (BASE_DIR / user_filename).resolve()

if BASE_DIR not in candidate.parents:
    raise ValueError("Invalid file path")

# Use a server-generated filename where appropriate.`,
    remediation:
      "Resolve the candidate path, enforce the upload jail, and add server-side filename, extension, size, and authorization controls.",
    validation:
      "The filename is classified in the browser only; the simulation does not access the host filesystem.",
    simulationNotice: "Educational simulation - the browser does not access the host filesystem.",
    samplePayloads: ["report.pdf", "../../sensitive.txt", "..%2f..%2fapp%2fconfig.py"],
    inputLabel: "Attacker-controlled filename",
  },
  creds: {
    id: "creds",
    priority: 3,
    cwe: "CWE-312",
    title: "Plaintext Password Storage",
    short: "Plaintext Passwords",
    severity: "High" as Severity,
    likelihood: "Medium",
    impactRating: "Critical",
    overallRisk: "High",
    reason: "Credential disclosure if storage is compromised",
    weakness: "Passwords are stored directly instead of using a password hashing algorithm.",
    danger:
      "A database disclosure immediately reveals reusable credentials, often expanding the compromise to other services.",
    scenario:
      "A registration request passes the password directly to `database.save`, making the stored value recoverable.",
    cvss: 9.1,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    owasp: "A02:2021 - Cryptographic Failures",
    mitre: "Contextual ATT&CK relationship: T1552 - Unsecured Credentials",
    file: "app/accounts.py",
    summary: "The account flow persists the original password rather than a password hash.",
    impact: [
      "Immediate disclosure of passwords after storage compromise",
      "Credential stuffing against reused passwords",
      "Password exposure through logs or API responses if handling is careless",
    ],
    fix: [
      "Use Argon2id with a unique random salt and appropriate work factors",
      "Never log or return passwords",
      "Rehash when parameters become outdated and protect recovery workflows",
    ],
    principles: ["Fail-Safe Defaults", "Defense in Depth", "Open Design"],
    before: `password = request.form["password"]
database.save(password)`,
    after: `from argon2 import PasswordHasher

hasher = PasswordHasher()
stored = hasher.hash(password)  # Argon2id record
database.save(stored)`,
    remediation:
      "Store only an Argon2id password hash, keep the password out of logs and responses, and rehash as work factors age.",
    validation:
      "The browser shows a simulated Argon2id record; it is not produced by a production authentication backend.",
    simulationNotice: "Simulated Argon2id record - no production database is used.",
    samplePayloads: ["hunter2", "Summer2024!", "correct horse battery staple"],
    inputLabel: "Password value for simulation",
  },
  deps: {
    id: "deps",
    priority: 4,
    cwe: "CWE-1395",
    title: "Unchecked / Outdated External Libraries",
    short: "Vulnerable Dependencies",
    severity: "High" as Severity,
    likelihood: "Context-dependent",
    impactRating: "High",
    overallRisk: "High",
    reason: "Known vulnerable components may expose application attack surface",
    weakness:
      "External dependencies are used without regularly checking for known vulnerabilities or maintaining secure versions.",
    danger:
      "A known vulnerability may be reachable through the application's configuration and functionality; severity is not universal for the CWE itself.",
    scenario:
      "An old package version is entered into the dependency simulator and matched against representative advisories.",
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    mitre:
      "Contextual ATT&CK relationship only; a vulnerable dependency is not inherently T1195.002 supply-chain compromise",
    file: "requirements.txt",
    summary:
      "Dependency versions are not continuously reviewed against known advisories or secure update policy.",
    impact: [
      "Known flaws may be reachable when affected functionality is enabled",
      "Transitive risk may remain invisible without an SBOM",
      "Patch delays increase the attack surface",
    ],
    fix: [
      "Pin dependencies and verify hashes where appropriate",
      "Run pip-audit and generate an SBOM in CI",
      "Use automated updates and security gates with regular review",
    ],
    principles: ["Defense in Depth", "Open Design", "Complete Mediation"],
    before: `# requirements.txt
requests==2.19.1
Jinja2==2.10
PyYAML==5.1
# no dependency security review`,
    after: `# Pin, review, and scan dependencies
requests==2.32.3
Jinja2==3.1.4
PyYAML==6.0.2

# CI control (representative)
pip-audit --strict -r requirements.txt`,
    remediation:
      "Pin maintained versions, scan routinely, produce an SBOM, verify integrity, and gate releases on reviewable results.",
    validation:
      "The dependency checks are representative browser simulations, not an actual pip-audit run in this frontend.",
    simulationNotice: "Simulated security pipeline output - no Python CI workflow runs here.",
    samplePayloads: ["requests==2.19.1", "Jinja2==2.10", "PyYAML==5.1"],
    inputLabel: "Dependency entry",
  },
  tmp: {
    id: "tmp",
    priority: 5,
    cwe: "CWE-377",
    title: "Predictable Temporary Files",
    short: "Predictable Temp Files",
    severity: "High" as Severity,
    likelihood: "Medium",
    impactRating: "High",
    overallRisk: "Medium-High",
    reason: "Race, collision, or local file access risk",
    weakness:
      "Temporary files are created using predictable names, creating a risk of collision, unauthorized access, or race conditions.",
    danger:
      "An attacker with local access may pre-create a path or win a race, redirecting output or reading temporary content.",
    scenario:
      "A fixed `/tmp/report.txt` name is opened without atomic exclusive creation or restrictive permissions.",
    cvss: 7.0,
    vector: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
    owasp: "A04:2021 - Insecure Design",
    mitre: "Contextual relationship only; CWE-377 is not inherently T1547 Boot or Logon Autostart",
    file: "app/exporter.py",
    summary:
      "Export jobs use a predictable temporary path rather than Python's secure temporary-file APIs.",
    impact: [
      "File collisions and data corruption",
      "Potential local disclosure of temporary content",
      "Race conditions that redirect writes",
    ],
    fix: [
      "Use tempfile.NamedTemporaryFile or tempfile.mkstemp",
      "Use restrictive permissions and a private directory",
      "Clean up through a context manager",
    ],
    principles: ["Fail-Safe Defaults", "Least Privilege", "Defense in Depth"],
    before: `filename = "/tmp/report.txt"
open(filename, "w")`,
    after: `import tempfile

with tempfile.NamedTemporaryFile(mode="w+", delete=True) as tmp:
    tmp.write(data)`,
    remediation:
      "Let Python create an exclusive temporary file with appropriate permissions and clean it up automatically.",
    validation:
      "The simulator displays a labeled server-generated filename; it does not claim deterministic output is cryptographic randomness.",
    simulationNotice: "Simulated server-generated temporary filename - no host file is created.",
    samplePayloads: ["123", "4471", "report-job"],
    inputLabel: "Job identifier",
  },
  except: {
    id: "except",
    priority: 6,
    cwe: "CWE-396",
    title: "Generic Exception Handling",
    short: "Generic Exception Handling",
    severity: "Medium" as Severity,
    likelihood: "High",
    impactRating: "Medium/context-dependent",
    overallRisk: "Medium",
    reason: "Can hide failures and create insecure fallback behavior",
    weakness:
      "Broad or bare exception handling can hide failures and may cause insecure fallback behavior.",
    danger:
      "A bare catch-all can hide authentication, authorization, integrity, or availability failures. Severity depends on the affected control.",
    scenario:
      "A failed authentication is caught by `except:` and the vulnerable function grants guest access instead of denying the request.",
    cvss: 6.5,
    vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
    owasp: "A09:2021 - Security Logging and Monitoring Failures",
    mitre: "Contextual ATT&CK relationship: T1562.008 - Impair Defenses",
    file: "app/auth_service.py",
    summary: "Broad exception handling can hide failures and return success-shaped responses.",
    impact: [
      "Authorization or authentication failures may fail open",
      "Security events may not be logged",
      "Data integrity and availability issues may be masked",
    ],
    fix: [
      "Catch narrow expected exception types",
      "Log security events without exposing internal details",
      "Use a final except Exception safety boundary only when it logs and fails closed",
    ],
    principles: ["Fail-Safe Defaults", "Defense in Depth"],
    before: `try:
    authenticate(user)
except:
    allow_access()`,
    after: `try:
    authenticate(user)
except InvalidCredentials:
    deny_access()
except DatabaseError:
    log_security_event()
    deny_access()
except Exception:
    log_unexpected_error()
    deny_access()`,
    remediation:
      "Handle expected failures explicitly and make the final safety boundary observable and fail closed.",
    validation:
      "The browser injects representative failure labels and compares fail-open versus fail-closed outcomes.",
    simulationNotice: "Educational simulation - no authentication service is connected.",
    samplePayloads: ["InvalidCredentials", "DatabaseError", "Unexpected failure"],
    inputLabel: "Simulated failure",
  },
};

export const VULNS: Vuln[] = [
  common.cmdi,
  common.path,
  common.creds,
  common.deps,
  common.tmp,
  common.except,
];
export const VULN_DB: Record<string, { cve: string; fixed: string; cvss: number; note: string }[]> =
  {
    "requests==2.19.1": [
      {
        cve: "CVE-2018-18074",
        fixed: "2.20.0",
        cvss: 7.5,
        note: "Authorization header leaked on redirect",
      },
    ],
    "Jinja2==2.10": [{ cve: "CVE-2019-10906", fixed: "2.10.1", cvss: 8.6, note: "Sandbox escape" }],
    "PyYAML==5.1": [
      { cve: "CVE-2020-1747", fixed: "5.3.1", cvss: 9.8, note: "Unsafe object construction" },
    ],
  };
export const PRINCIPLES = [
  {
    name: "Complete Mediation",
    body: "Every security-sensitive operation must validate authorization and input at the point of use.",
    applies: ["Command Injection", "Path Traversal", "Dependencies"],
    applied:
      "Host validation, path containment, and dependency review occur before the sensitive operation.",
  },
  {
    name: "Defense in Depth",
    body: "Use independent, overlapping controls so one bypass does not become a compromise.",
    applies: [
      "Command Injection",
      "Path Traversal",
      "Passwords",
      "Dependencies",
      "Temporary Files",
      "Exception Handling",
    ],
    applied:
      "The modules combine validation, least privilege, logging, safe APIs, scanning, and fail-closed behavior.",
  },
  {
    name: "Fail-Safe Defaults",
    body: "Security failures should default to denial rather than granting access.",
    applies: ["Passwords", "Exception Handling", "Path Traversal", "Temporary Files"],
    applied:
      "Invalid paths, authentication failures, and unsafe temporary-file states are refused.",
  },
  {
    name: "Least Privilege",
    body: "Each component should use the minimum rights needed for the shortest time.",
    applies: ["Command Injection", "Temporary Files"],
    applied:
      "No shell is used, and temporary storage uses private directories and restrictive permissions.",
  },
  {
    name: "Economy of Mechanism",
    body: "Prefer simple, auditable mechanisms with a small surface area.",
    applies: ["Command Injection"],
    applied: "An argument list and strict validator are easier to review than shell escaping.",
  },
  {
    name: "Open Design",
    body: "Security should rely on sound controls and protected secrets, not hidden implementation details.",
    applies: ["Passwords", "Dependencies"],
    applied:
      "Published Argon2id parameters and transparent dependency review support repeatable assessment.",
  },
];
export const severityColor = (s: Severity) =>
  s === "Critical"
    ? "text-danger border-danger/40 bg-danger/10"
    : s === "High"
      ? "text-warn border-warn/40 bg-warn/10"
      : s === "Medium"
        ? "text-accent border-accent/40 bg-accent/10"
        : "text-muted-foreground border-border bg-muted/40";
