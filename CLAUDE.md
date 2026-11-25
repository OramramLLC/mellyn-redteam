# CLAUDE.md — Project Context & OWASP AI Security Guardrails

## Project Overview
This repository houses **Mellyn Redteam**, the standalone adversarial evaluation and OWASP/ATLAS control conformance harness for the Mellyn Security runtime (`OramramLLC/mellyn_security`):

- **Adversarial Scorecard (`examples/adversarial_eval/`)**: 25 deterministic MCP runtime attack scenarios across Supply Chain & AgBOM, Protocol & Framing, Workspace & Paths, Egress & Canaries, and Forensic Ledger Integrity.
- **Observe-Mode Red-Team Workflow (`examples/observe_redteam/`)**: Multi-turn indirect prompt-injection trajectory comparing `--mode observe --record-redacted-payloads`, anti-downgrade refusal, and `--mode enforce` with CLI, JSON, and Markdown (`mellyn-ir`) outputs.
- **Control Assurance Suite (`tests/conformance/`, `scripts/run_conformance_report.py`)**: Versioned OWASP LLM Top 10 / Agentic Top 10 / MITRE ATLAS conformance evidence recorder (`fast` runtime profile + declarative `linux-container` specs).
- **Benchmark Wrapper (`scripts/run_benchmark.py`)**: Runs `mellyn-bench --json` via subprocess against the installed core package (`pip install -e ../V1`).
- **Contract Documentation (`PUBLIC_SURFACE.md`)**: Enumerates every `mellyn.*` and `mcp_airlock.*` import and CLI command consumed from `OramramLLC/mellyn_security`.

## Essential Commands
On Windows, use `py` instead of `python` if `python` opens the Microsoft Store.

- **Install core runtime from local checkout**: `python -m pip install -e ../V1` (not declared in `pyproject.toml`)
- **Run unit & E2E suites**: `python -m unittest discover -s tests -v` (requires installed `mellyn-security` core)
- **Run 25-case adversarial scorecard**: `python examples/adversarial_eval/run_redteam.py`
- **Run live `--mode observe` red-team workflow**: `python examples/observe_redteam/run_observe_workflow.py`
- **Run conformance report generator**: `python scripts/run_conformance_report.py --json-out artifacts/conformance-fast.json --markdown-out artifacts/conformance-fast.md`
- **Run egress scanner benchmark CLI**: `mellyn-bench --json` (or `python scripts/run_benchmark.py`)
- **Run Ruff lint & format checks**: `ruff check .` and `ruff format --check .`
- **Run guardrail hooks**: `pre-commit run --all-files` (pinned `OramramLLC/mellyn-guardrails` hooks)

## Mandatory Security Rules
The canonical ruleset is maintained in `OramramLLC/mellyn-guardrails`. Keep the local copies (`.agent/rules/owasp-secure-ai-coding.md`, `.cursorrules`, `.github/copilot-instructions.md`) unmodified unless updating from the pinned guardrail pack, verified by `mellyn-check-agent-rules` (`--check --require-pack-canonical`) in pre-commit and CI. Secret-shaped test strings must always be constructed at runtime rather than stored as literals.

@.agent/rules/owasp-secure-ai-coding.md
