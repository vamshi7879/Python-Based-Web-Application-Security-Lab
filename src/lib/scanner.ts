export type ScannerSeverity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export type ScannerFinding = {
  id: string;
  category: string;
  severity: ScannerSeverity;
  priority: number;
  line: number;
  title: string;
  description: string;
  impact: string;
  recommendation: string;
  secureExample: string;
  principles: string[];
  confidence: "High" | "Medium" | "Low";
  detectedPattern: string;
};

export type ScanResult = {
  success: boolean;
  syntaxValid: boolean;
  error?: string;
  findings: ScannerFinding[];
  score: number;
  summary: Record<"Critical" | "High" | "Medium" | "Low" | "Informational", number>;
  lines: string[];
};

export const SCAN_SAMPLES = {
  high: {
    name: "High vulnerability",
    description: "Multiple case-study weaknesses in one small Python module.",
    code: `import os
import requests

username = input("Enter username: ")
filename = input("Enter filename: ")
password = input("Enter password: ")

os.system("ping " + username)

with open(filename, "r") as file:
    data = file.read()

users = {}
users[username] = password

try:
    process_data(data)
except:
    pass

temp_file = "/tmp/report.txt"

response = requests.get("https://example.com")`,
  },
  medium: {
    name: "Medium vulnerability",
    description: "A smaller set of weaknesses for comparing scan results.",
    code: `import os

filename = input("Enter filename: ")
username = input("Enter username: ")

with open(filename, "r") as file:
    data = file.read()

try:
    print(data)
except:
    print("An error occurred")

password = "temporary_password"`,
  },
  safe: {
    name: "No high-risk vulnerabilities",
    description: "Safer APIs and explicit validation; static analysis still cannot prove security.",
    code: `from pathlib import Path
import tempfile
import hashlib

def validate_username(username):
    if not username.isalnum():
        raise ValueError("Invalid username")
    return username

def read_user_file(filename):
    base_directory = Path("uploads").resolve()
    requested_file = (base_directory / filename).resolve()
    if base_directory not in requested_file.parents:
        raise ValueError("Invalid file path")
    return requested_file.read_text(encoding="utf-8")

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def create_temp_file(content):
    with tempfile.NamedTemporaryFile(mode="w", delete=True, encoding="utf-8") as temp_file:
        temp_file.write(content)
        return temp_file.name`,
  },
} as const;

const SCORE_DEDUCTIONS: Record<ScannerSeverity, number> = {
  Critical: 25,
  High: 15,
  Medium: 8,
  Low: 3,
  Informational: 0,
};

const PRINCIPLES = {
  command: ["Input Validation", "Least Privilege", "Defense in Depth", "Minimize Attack Surface"],
  path: ["Input Validation", "Least Privilege", "Defense in Depth", "Secure Defaults"],
  password: ["Secure Data Storage", "Defense in Depth", "Least Privilege"],
  exception: ["Secure Failure", "Defense in Depth", "Auditability"],
  temp: ["Secure Defaults", "Defense in Depth", "Minimize Attack Surface"],
  dependency: ["Dependency Management", "Minimize Attack Surface"],
};

function finding(
  data: Omit<ScannerFinding, "id"> & { code: string },
  index: number,
): ScannerFinding {
  const { code, ...rest } = data;
  return { ...rest, id: `${code}-${String(index).padStart(3, "0")}` };
}

function syntaxCheck(source: string): string | undefined {
  const stack: string[] = [];
  const pairs: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  for (const character of source) {
    if ("([{".includes(character)) stack.push(character);
    if (")]}".includes(character) && stack.pop() !== pairs[character]) {
      return "Python syntax error: unmatched bracket or parenthesis.";
    }
  }
  if (
    stack.length > 0 ||
    /(^|\n)\s*(if|for|while|def|class|try|with)\b[^\n]*[^:]\s*(#.*)?$/.test(source)
  ) {
    return "Python syntax error: an expected block delimiter or closing bracket is missing.";
  }
  if ((source.match(/'''/g)?.length ?? 0) % 2 || (source.match(/"""/g)?.length ?? 0) % 2) {
    return "Python syntax error: unterminated multiline string.";
  }
  return undefined;
}

export function analyzePython(source: string): ScanResult {
  const lines = source.split(/\r?\n/);
  if (!source.trim()) {
    return {
      success: false,
      syntaxValid: true,
      error: "Add Python source code before scanning.",
      findings: [],
      score: 0,
      summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
      lines,
    };
  }
  if (source.length > 200_000) {
    return {
      success: false,
      syntaxValid: true,
      error: "Source exceeds the 200 KB prototype limit.",
      findings: [],
      score: 0,
      summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
      lines,
    };
  }
  const syntaxError = syntaxCheck(source);
  if (syntaxError) {
    return {
      success: false,
      syntaxValid: false,
      error: syntaxError,
      findings: [],
      score: 0,
      summary: { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 },
      lines,
    };
  }

  const findings: ScannerFinding[] = [];
  const inputNames = new Set<string>();
  lines.forEach((line, index) => {
    const lineNumber = index + 1;
    const inputMatch = line.match(/\b([A-Za-z_]\w*)\s*=\s*input\s*\(/);
    if (inputMatch) inputNames.add(inputMatch[1]!);
    const dynamic = [...inputNames].some((name) => new RegExp(`\\b${name}\\b`).test(line));

    if (
      /\bos\.(system|popen)\s*\(/.test(line) ||
      (/\bsubprocess\.(run|Popen|call|check_output)\s*\(/.test(line) &&
        /\bshell\s*=\s*True/.test(line))
    ) {
      findings.push(
        finding(
          {
            code: "CMD",
            category: "Command Injection",
            severity: dynamic ? "Critical" : "High",
            priority: 1,
            line: lineNumber,
            title: "Potential Command Injection",
            description:
              "A command execution API receives a value that may be dynamically constructed from source input.",
            impact:
              "An attacker may potentially influence command execution with the process account's permissions.",
            recommendation:
              "Avoid shell execution, validate against an allowlist, and pass a fixed argument list with shell=False.",
            secureExample: 'subprocess.run(["ping", "-c", "1", validated_host], check=True)',
            principles: PRINCIPLES.command,
            confidence: dynamic ? "High" : "Medium",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
    if (/\bopen\s*\(\s*[A-Za-z_]\w*/.test(line) && dynamic) {
      findings.push(
        finding(
          {
            code: "PATH",
            category: "Unsafe File Access",
            severity: "High",
            priority: 2,
            line: lineNumber,
            title: "Potential Unsafe File Access",
            description:
              "A file path derived from input is passed to open without visible containment validation.",
            impact:
              "An attacker may potentially access files outside the intended application directory.",
            recommendation:
              "Resolve a trusted base directory and candidate path, then verify the candidate remains inside the base.",
            secureExample:
              'candidate = (base / filename).resolve()\nif base not in candidate.parents: raise ValueError("Invalid path")',
            principles: PRINCIPLES.path,
            confidence: "High",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
    if (
      /\b(password|passwd|plain_password|credential)\b/i.test(line) &&
      /\[.*\]\s*=|\.\s*(save|insert|write)\s*\(|=\s*["']/.test(line)
    ) {
      findings.push(
        finding(
          {
            code: "PWD",
            category: "Plaintext Password Handling",
            severity: /\[.*\]\s*=|\.\s*(save|insert|write)\s*\(/.test(line) ? "High" : "Medium",
            priority: 3,
            line: lineNumber,
            title: "Potential Plaintext Password Handling",
            description:
              "A password-like value appears to be assigned or stored without evidence of a password-specific hash.",
            impact:
              "A data-store disclosure could reveal reusable credentials and enable credential stuffing.",
            recommendation:
              "Hash passwords with Argon2id, bcrypt, or scrypt; never log, display, or persist the original value.",
            secureExample: "stored = password_hasher.hash(password)\nusers[user] = stored",
            principles: PRINCIPLES.password,
            confidence: "Medium",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
    if (/^\s*except\s*:\s*$/.test(line)) {
      findings.push(
        finding(
          {
            code: "EXC",
            category: "Generic Exception Handling",
            severity: "Medium",
            priority: 5,
            line: lineNumber,
            title: "Generic Exception Handling",
            description:
              "A bare except catches every exception, including unexpected security and system failures.",
            impact:
              "Unexpected failures can be hidden, impairing reliable monitoring and secure failure behavior.",
            recommendation:
              "Catch specific expected exceptions, log safely, and fail closed at a final safety boundary.",
            secureExample: "except ValueError as error:\n    log_validation_error(error)",
            principles: PRINCIPLES.exception,
            confidence: "High",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
    if (/['"]\/tmp\/[^'"]+['"]/.test(line)) {
      findings.push(
        finding(
          {
            code: "TMP",
            category: "Predictable Temporary File",
            severity: "Medium",
            priority: 4,
            line: lineNumber,
            title: "Predictable Temporary File",
            description:
              "A hardcoded temporary path can collide or be targeted by another local process.",
            impact:
              "Temporary content may be disclosed, overwritten, or redirected through a race condition.",
            recommendation:
              "Use tempfile.NamedTemporaryFile or tempfile.TemporaryDirectory with automatic cleanup.",
            secureExample:
              'with tempfile.NamedTemporaryFile(mode="w", delete=True) as temp_file:\n    temp_file.write(content)',
            principles: PRINCIPLES.temp,
            confidence: "High",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
  });

  const stdlib = new Set([
    "os",
    "sys",
    "pathlib",
    "tempfile",
    "hashlib",
    "subprocess",
    "json",
    "re",
    "typing",
    "logging",
  ]);
  lines.forEach((line, index) => {
    const match = line.match(/^\s*(?:import|from)\s+([A-Za-z_]\w*)/);
    if (match && !stdlib.has(match[1]!)) {
      findings.push(
        finding(
          {
            code: "DEP",
            category: "Dependency Security Review",
            severity: "Informational",
            priority: 6,
            line: index + 1,
            title: "Dependency Security Review Required",
            description: `External dependency '${match[1]}' was identified; this is not proof of a vulnerable version.`,
            impact:
              "Unreviewed dependencies can add avoidable attack surface or known vulnerable transitive code.",
            recommendation:
              "Pin maintained versions and review them with a trusted advisory database or pip-audit in CI.",
            secureExample: "requests==2.32.3\npip-audit --strict -r requirements.txt",
            principles: PRINCIPLES.dependency,
            confidence: "High",
            detectedPattern: line.trim(),
          },
          findings.length + 1,
        ),
      );
    }
  });

  const summary = { Critical: 0, High: 0, Medium: 0, Low: 0, Informational: 0 };
  findings.forEach((item) => summary[item.severity]++);
  const score = Math.max(
    0,
    100 - findings.reduce((total, item) => total + SCORE_DEDUCTIONS[item.severity], 0),
  );
  return { success: true, syntaxValid: true, findings, score, summary, lines };
}

export function buildScanReport(source: string, result: ScanResult): string {
  return `# Secure Coding Assessment Report\n\n## Executive Summary\n${result.findings.length ? `${result.findings.length} potential finding(s) require review.` : "No configured high-risk patterns detected."} Educational score: ${result.score}/100.\n\n## Scope\nPython source text analyzed by the configured defensive rules. Submitted code was never executed.\n\n## Methodology\nStatic source inspection, syntax validation, rule-based finding normalization, severity, priority, recommendations, and principle mapping.\n\n## Findings\n${result.findings.map((item) => `- ${item.id} ${item.title} (${item.severity}) at line ${item.line}: ${item.description}`).join("\n") || "No findings."}\n\n## Limitations\nThis is an educational static-analysis prototype, not a penetration test. It performs no runtime analysis or complete taint analysis, may produce false positives and false negatives, and does not verify dependency CVEs without a configured trusted database. Manual verification is required.\n\n## Source\n\`\`\`python\n${source}\n\`\`\`\n`;
}
