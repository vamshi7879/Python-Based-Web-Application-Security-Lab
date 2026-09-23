# Python Web Application Security Case Study

An educational web application security laboratory demonstrating six secure-coding weaknesses through controlled browser-based simulations and representative vulnerable and hardened Python examples.

## Case Study

The scenario describes a Python-based web application that accepts user input, processes files supplied by users, executes system commands, and stores user credentials. A security review identified six weaknesses:

1. OS Command Injection - CWE-78
2. Path Traversal - CWE-22
3. Plaintext Passwords - CWE-312
4. Unchecked / Outdated External Libraries - CWE-1395
5. Predictable Temporary Files - CWE-377
6. Generic Exception Handling - CWE-396

## Contents

- Risk assessment with likelihood, impact, overall risk, and priority
- Prioritization rationale
- Secure coding principles: Complete Mediation, Defense in Depth, Fail-Safe Defaults, Least Privilege, Economy of Mechanism, and Open Design
- Representative vulnerable and hardened Python examples
- Remediation guidance and validation demonstrations
- Simulated DevSecOps pipeline
- Security assessment report and rubric coverage

## Educational Safety Notice

The current frontend is a simulation and does not execute attacker-supplied operating-system commands or access the host filesystem. It does not use a production database, process real uploads, or run pytest, pip-audit, Bandit, or a Python CI workflow. Pipeline output and validation are representative educational examples.

## Limitations

This project is not a vulnerable Python server. Browser inputs are classified by TypeScript simulation logic, and the representative Python snippets are provided for secure-coding analysis only. Advisory severity belongs to the underlying CVE where shown; application-specific risk depends on reachability, configuration, permissions, and affected functionality.

## Development

```sh
npm install
npm run dev
```

Available checks:

```sh
npm run build
npm run lint
```

The project is a standalone React/TypeScript application using Vite and TanStack routing.
