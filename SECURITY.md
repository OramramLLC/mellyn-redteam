# Security Policy

## Scope

This repository (`mellyn-redteam`) contains synthetic adversarial scenarios, `--mode observe` red-team harnesses, and conformance test suites targeting the Mellyn Security Core Runtime (`OramramLLC/mellyn_security`).

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for suspected security vulnerabilities.**

- If a finding exposes a bypass, fail-open behavior, or containment flaw in the core proxy, authorizer, egress scanner, or flight recorder, report it privately via **GitHub Security Advisories** (`Security` tab -> `Report a vulnerability`) on `OramramLLC/mellyn_security` (or on this repository if the flaw is in conformance reporting or synthetic-data handling).
- Include reproduction steps, impacted file/control IDs, and runtime environment details (OS, Python version, and pinned `OramramLLC/mellyn_security` commit SHA).

---

## Evaluation & Data Hygiene Rules

- **Synthetic Fixtures Only:** All canary tokens, sample API keys, tickets, and MCP servers in this repository are disposable synthetic fixtures. Secret-shaped test tokens (such as AWS/OpenAI formats) are assembled dynamically at runtime rather than committed as raw literals.
- **Observability Privacy Notice:** `--mode observe --record-redacted-payloads` logs truncated (16 KiB) redacted request/response payloads for allowed turns as well as blocks; use it strictly with isolated red-team harnesses and synthetic throwaway canaries.
- **Detection Is a Tripwire, Not a Boundary:** Adversarial scorecard coverage regressions test known encoding and evasion patterns (see [`examples/adversarial_eval/README.md`](examples/adversarial_eval/README.md) "What this does not cover"). Hard containment guarantees live in `OramramLLC/mellyn_security` network egress isolation and fail-closed tool policy enforcement.
