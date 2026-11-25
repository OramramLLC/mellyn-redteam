# Mellyn Core Public Surface Used by `mellyn-redteam`

This document records every Python import, internal helper dependency, CLI command, and wire/report contract that `mellyn-redteam` consumes from `OramramLLC/mellyn_security` (`pip install -e ../V1`). Phase 2 package consolidation must preserve these entrypoints or update both repositories together.

Wherever a subprocess CLI (`mellyn-airlock`, `mellyn-ir`, `mellyn-bench`) covers a workflow step, `mellyn-redteam` invokes the CLI rather than copying or importing internal implementation modules.

---

## 1. Python Imports: `mellyn.*`

| Module | Imported Symbols | Used By | Stability / Phase 2 Note |
| :--- | :--- | :--- | :--- |
| `mellyn` | `AuditLogger`, `Authorizer`, `CredentialConfig`, `CredentialConfigError`, `Decision`, `PolicyConfig`, `RiskTier`, `Role`, `TaintSource`, `ToolCallRequest`, `ToolCapability` | `tests/conformance/cases.py` | Public top-level exports from `backend/mellyn/__init__.py` |
| `mellyn.approvals` | `ApprovalRedirectError`, `PENDING_TTL_SECONDS`, `PendingApprovals`, `build_approval_opener` | `tests/conformance/cases.py` | Approval workflow & redirect-refusal opener |
| `mellyn.audit` | `EMPTY_ARGS_SHA256` | `tests/conformance/recorder.py` | Shared canonical empty-arguments SHA-256 constant |
| `mellyn.credentials` | `key_digest` | `tests/conformance/cases.py` | HMAC-SHA256 API key digest helper |
| `mellyn.egress` | `WorkspacePathGuard` | `examples/adversarial_eval/run_redteam.py` | Workspace path confinement parity check alongside `mcp_airlock` |
| `mellyn.legacy_env` | `check_no_legacy_env` | `examples/observe_redteam/run_observe_workflow.py` | Fail-closed pre-rename environment variable check |
| `mellyn.mcp_gateway` | `DOWNSTREAM_ERROR`, `JSONRPC_INVALID_PARAMS`, `JSONRPC_INVALID_REQUEST`, `JSONRPC_PARSE_ERROR`, `MELLYN_APPROVAL_REQUIRED`, `MELLYN_POLICY_DENIED`, `MCPGateway`, `compute_tools_hash`, `run_stdio_proxy` | `tests/conformance/cases.py` | Public gateway classes, AgBOM hash helper, and JSON-RPC error constants |
| `mellyn.mcp_gateway` | `_local_downstream_error` | `tests/fakes.py` | **Internal helper** (`_` prefixed): constructs gateway-originated timeout envelope in `FakeDownstream`; Phase 2 should promote or replace with a public factory |
| `mellyn.models` | `canonical_json` | `tests/conformance/recorder.py` | Canonical JSON serialization for conformance `args_sha256` verification |

---

## 2. Python Imports: `mcp_airlock.*`

| Module | Imported Symbols | Used By | Stability / Phase 2 Note |
| :--- | :--- | :--- | :--- |
| `mcp_airlock.airlock.engine` | `compute_tool_pin`, `evaluate_tool_call` | `examples/adversarial_eval/run_redteam.py` | Direct tool-pin computation & policy verdict unit probe |
| `mcp_airlock.airlock.models` | `AirlockPolicy`, `JsonRpcRequest`, `ToolDefinition`, `ToolPolicyRule`, `parse_jsonrpc_bytes` | `examples/adversarial_eval/run_redteam.py` | Wire schema models & strict duplicate-key/NaN parser |
| `mcp_airlock.airlock.models` | `parse_airlock_policy_toml` | `tests/e2e/test_observe_redteam_workflow.py` | Policy TOML parser for pin parity assertions |
| `mcp_airlock.airlock.pin_cli` | `inspect_mcp_server` | `tests/e2e/test_observe_redteam_workflow.py` | Async quarantined tool manifest pinner check |
| `mcp_airlock.airlock.proxy` | `AAD_EXIT_CODE`, `AirlockProxy`, `JSONRPC_AAD_CONTAINMENT_SEVERED`, `JSONRPC_POLICY_VIOLATION` | `examples/adversarial_eval/run_redteam.py`, `examples/observe_redteam/run_observe_workflow.py`, `tests/e2e/test_observe_redteam_workflow.py` | Proxy harness driver & exit/JSON-RPC error constants (`AirlockProxy` in-process stream driver used in adversarial suite; `mellyn-airlock` CLI used in observe workflow) |
| `mcp_airlock.core.audit` | `AuditLedger` | `examples/adversarial_eval/run_redteam.py` | Hash-chained flight recorder writer |
| `mcp_airlock.core.audit` | `canary_present`, `canary_present_in_json` | `examples/observe_redteam/run_observe_workflow.py` | Redaction verification helper across output files (avoid duplicating scanner detection logic) |
| `mcp_airlock.core.schemas` | `ZoneEvent` | `examples/adversarial_eval/run_redteam.py` | Typed ledger event schema |
| `mcp_airlock.egress.guards` | `WorkspacePathGuard` | `examples/adversarial_eval/run_redteam.py` | Airlock path confinement guard |
| `mcp_airlock.egress.scanner` | `scan_payload` | `examples/adversarial_eval/run_redteam.py` | Secret/canary scanner verdict probe |
| `mcp_airlock.ir_lab.reconstruct` | `IncidentReport` | `examples/observe_redteam/run_observe_workflow.py` | Strict Pydantic model validating `mellyn-ir --json` output |
| `mcp_airlock.ir_lab.reconstruct` | `reconstruct_incident` | `examples/adversarial_eval/run_redteam.py` | Incident chain & AAD state reconstructor |

---

## 3. CLI Commands (`pyproject.toml` `[project.scripts]` in `OramramLLC/mellyn_security`)

| Command | Entrypoint Target | Invocation Status in `mellyn-redteam` | Flags / Contract Consumed |
| :--- | :--- | :--- | :--- |
| `mellyn-airlock` | `mcp_airlock.airlock.proxy:main` | **Invoked via subprocess** (`examples/observe_redteam/run_observe_workflow.py`) | `--policy`, `--audit-log`, `--session-id`, `--mode observe\|enforce`, `--record-redacted-payloads`, `-- <cmd...>`; stdio JSON-RPC framing |
| `mellyn-ir` | `mcp_airlock.ir_lab.reconstruct:main` | **Invoked via subprocess** (`examples/observe_redteam/run_observe_workflow.py`) | `<ledger.jsonl> --json` (JSON output parsed via `IncidentReport.model_validate_json`), `<ledger.jsonl>` (Markdown report to stdout) |
| `mellyn-bench` | `mcp_airlock.egress.bench:main` | **Invoked via subprocess** (`scripts/run_benchmark.py`, `tests/e2e/test_bench_cli.py`) | `--iterations <N> --json` (emits `BenchmarkReport` JSON; exits `0` on pass, `1` on missed secret/canary) |
| `mellyn` | `mellyn.cli:main` | Reserved core entrypoint (not currently invoked directly; conformance tests call Python `mellyn.*` APIs in-process) | Gateway/authorizer management CLI |
| `mellyn-pin` | `mcp_airlock.airlock.pin_cli:main` | Reserved core entrypoint (pin parity currently verified via `inspect_mcp_server` in `tests/e2e/test_observe_redteam_workflow.py`) | Quarantined MCP server AgBOM manifest pin generator |

---

## 4. Wire, Exit-Code, and Schema Contracts Relied Upon

- **Process exit codes:** `0` (clean / allowed / valid hash chain), `2` (`mellyn-airlock --mode observe` refused when `allow_observe_mode = false`, invalid CLI args, or invalid ledger in `mellyn-ir`), `78` (`AAD_EXIT_CODE` immediate session termination).
- **Refusal message contract:** `mellyn-airlock` prints ``--mode observe requires `allow_observe_mode = true` `` on stderr when refusing observe downgrade.
- **JSON-RPC error codes:** `-32000` (`JSONRPC_POLICY_VIOLATION`), `-32099` (`JSONRPC_AAD_CONTAINMENT_SEVERED`), and `mellyn.mcp_gateway` constants (`MELLYN_POLICY_DENIED`, `MELLYN_APPROVAL_REQUIRED`, `JSONRPC_PARSE_ERROR`, `JSONRPC_INVALID_REQUEST`, `JSONRPC_INVALID_PARAMS`, `DOWNSTREAM_ERROR`).
- **Benchmark JSON fields (`mellyn-bench --json`):** `total_samples`, `precision`, `recall`, `canary_recall`, `false_positives`, `false_negatives`, `p50_us_per_kb`, `p99_us_per_kb`, `passed`.
- **Audit JSONL fields (`AuditEvent`):** Conformance cases verify presence and digests for `audit_id`, `timestamp`, `session_id`, `tool_name`, `mcp_server`, `decision`, `risk_tier`, `tainted`, `taint_sources`, `args_sha256`, `reasons`, `policy_id`, `grant_id`, `event_type`, and `taint_count`.
