# Mellyn Redteam — Adversarial Evaluation & OWASP/ATLAS Conformance Suite

**Mellyn Redteam** is the standalone evaluation, live `--mode observe` red-team, and control assurance harness for **`OramramLLC/mellyn_security`** (Core MCP Runtime: Airlock proxy, Runtime Authorizer, Egress Scanner, and Forensic Flight Recorder).

---

## Components

1. **Adversarial Scorecard ([`examples/adversarial_eval/`](examples/adversarial_eval/README.md))** — 25 deterministic MCP runtime attack scenarios across Supply Chain & AgBOM Tampering, Protocol & Framing Attacks, Workspace & Path Confinement, Egress & Canary Exfiltration, and Forensic Ledger Integrity.
2. **Live `--mode observe` Red-Team Workflow ([`examples/observe_redteam/`](examples/observe_redteam/README.md))** — End-to-end indirect prompt-injection kill-chain executed through `mellyn-airlock` and reconstructed with `mellyn-ir`, validating `--mode observe --record-redacted-payloads`, anti-downgrade refusal (`exit 2`), `--mode enforce` containment (`-32000` / `-32099`, `exit 78`), CLI summaries, JSON/Markdown incident reports, and zero canary leakage across all six artifacts.
3. **OWASP & MITRE ATLAS Conformance Suite (`tests/conformance/`, [`scripts/run_conformance_report.py`](scripts/run_conformance_report.py))** — 12 `fast` runtime control cases plus 2 declarative `linux-container` specs mapped to OWASP LLM Top 10 `2025`, OWASP Agentic Top 10 `2026`, and MITRE ATLAS `5.6.0`.
4. **Egress Scanner Benchmark Wrapper ([`scripts/run_benchmark.py`](scripts/run_benchmark.py))** — Invokes `mellyn-bench --json` via subprocess and validates precision, recall, canary recall, and latency metrics without duplicating core scanner internals.
5. **Public Surface Contract ([`PUBLIC_SURFACE.md`](PUBLIC_SURFACE.md), [`tests/test_public_surface.py`](tests/test_public_surface.py))** — AST-enforced inventory of every `mellyn.*` import and CLI entrypoint consumed from `OramramLLC/mellyn_security`.

---

## Local Setup

Install `mellyn-security` from a local core checkout (`OramramLLC/mellyn_security` under `src/mellyn/` — it is intentionally not declared in [`pyproject.toml`](pyproject.toml)):

```bash
python -m pip install --require-hashes --no-deps -r ../V1/deploy/requirements-ci-tests.lock
python -m pip install --require-hashes --no-deps -r deploy/requirements-ci-build.lock
python -m pip install --no-deps --no-build-isolation -e ../V1
```

`--no-build-isolation` makes pip build the core with the hash-locked setuptools from
[`deploy/requirements-ci-build.lock`](deploy/requirements-ci-build.lock) instead of downloading an unpinned one.

In CI ([`.github/workflows/redteam-ci.yml`](.github/workflows/redteam-ci.yml)), `OramramLLC/mellyn_security` is checked out at a pinned commit SHA into `core/` and installed the same way.

---

## Running Evaluations & Tests

```bash
# Full test & conformance suite (adversarial E2E, observe workflow, conformance report, benchmark CLI, contract tests)
python -m unittest discover -s tests -v

# 25-scenario adversarial scorecard
python examples/adversarial_eval/run_redteam.py

# Live --mode observe vs. --mode enforce red-team workflow (writes CLI summary + JSON + Markdown reports)
python examples/observe_redteam/run_observe_workflow.py --output-dir artifacts/observe

# OWASP/ATLAS Control Assurance Report (fast profile)
python scripts/run_conformance_report.py --json-out artifacts/conformance-fast.json --markdown-out artifacts/conformance-fast.md

# Core egress scanner benchmark CLI (subprocess wrapper + direct JSON CLI)
mellyn-bench --json
python scripts/run_benchmark.py
```

### Lint & Guardrails

```bash
ruff check .
ruff format --check .
pre-commit run --all-files
```

---

## Sibling Repositories

- **`OramramLLC/mellyn_security`** — Core MCP runtime (`mellyn.airlock`, `mellyn.core`, `mellyn.egress`, `mellyn.ir_lab`, and authorization/gateway modules under `src/mellyn/`, plus optional Docker/Squid stack).
- **`OramramLLC/mellyn-guardrails`** — Reusable Gitleaks, Semgrep, AI instruction rules parity, and anti-slopsquatting dependency verifier pack pinned by commit SHA in [`.pre-commit-config.yaml`](.pre-commit-config.yaml) and [`.github/workflows/redteam-ci.yml`](.github/workflows/redteam-ci.yml).
