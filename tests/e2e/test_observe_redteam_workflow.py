"""E2E regression tests for the live `--mode observe` red-team workflow (CLI, JSON, and Markdown reports)."""

from __future__ import annotations

import asyncio
import io
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mellyn.airlock.models import parse_airlock_policy_toml  # noqa: E402
from mellyn.airlock.pin_cli import inspect_mcp_server  # noqa: E402
from mellyn.airlock.proxy import (  # noqa: E402
    AAD_EXIT_CODE,
    JSONRPC_AAD_CONTAINMENT_SEVERED,
    JSONRPC_POLICY_VIOLATION,
)

from examples.observe_redteam import run_observe_workflow as workflow_module  # noqa: E402
from examples.observe_redteam.run_observe_workflow import (  # noqa: E402
    ENFORCE_POLICY_PATH,
    OBSERVE_POLICY_PATH,
    OBSERVE_REFUSAL_MESSAGE,
    SERVER_PATH,
    _send_and_read,
    run_observe_workflow,
)


class TestObserveRedTeamWorkflow(unittest.TestCase):
    def test_observe_and_enforce_policies_match_sandbox_server_pins(self) -> None:
        inspection = asyncio.run(inspect_mcp_server([sys.executable, str(SERVER_PATH)]))
        self.assertEqual(inspection.warnings, [])

        observe_policy = parse_airlock_policy_toml(OBSERVE_POLICY_PATH.read_text(encoding="utf-8"))
        enforce_policy = parse_airlock_policy_toml(ENFORCE_POLICY_PATH.read_text(encoding="utf-8"))

        self.assertTrue(observe_policy.allow_observe_mode)
        self.assertFalse(enforce_policy.allow_observe_mode)
        self.assertEqual(inspection.manifest_sha256, observe_policy.manifest_sha256)
        self.assertEqual(inspection.manifest_sha256, enforce_policy.manifest_sha256)
        self.assertEqual(inspection.tool_pins, observe_policy.agbom_pins)
        self.assertEqual(inspection.tool_pins, enforce_policy.agbom_pins)

    def test_observe_workflow_captures_killchain_and_writes_cli_json_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            res = run_observe_workflow(Path(tmp))

            # Observe stage executes all turns, logs telemetry, and no ledger or report holds the canary in any
            # encoding the airlock detects (raw, Base64, hex, escapes, or pieces split across fields).
            self.assertEqual(res.observe_exit_code, 0)
            self.assertEqual(res.canary_leak_files, ())
            self.assertTrue(res.observe_audit_path.is_file())
            self.assertTrue(res.observe_report_path.is_file())
            self.assertTrue(res.observe_markdown_path.is_file())
            self.assertTrue(res.enforce_audit_path.is_file())
            self.assertTrue(res.enforce_report_path.is_file())
            self.assertTrue(res.enforce_markdown_path.is_file())
            self.assertIn("result", res.observe_turn_responses["turn1_list_tickets"])
            self.assertIn("result", res.observe_turn_responses["turn2_read_env"])
            self.assertIn("result", res.observe_turn_responses["turn3_post_webhook"])

            obs_rep = res.observe_report
            self.assertTrue(obs_rep.chain_valid)
            self.assertEqual(obs_rep.status, "OBSERVED_VIOLATIONS")
            self.assertGreaterEqual(obs_rep.observed_block_count, 1)
            self.assertGreaterEqual(obs_rep.observed_aad_count, 2)
            self.assertEqual(len(obs_rep.sessions), 1)
            self.assertEqual(obs_rep.sessions[0].enforcement_mode, "observe")

            obs_md = res.observe_markdown_path.read_text(encoding="utf-8")
            self.assertIn("# Mellyn Incident Reconstruction (OBSERVED_VIOLATIONS)", obs_md)
            self.assertIn("**Mode**: observe", obs_md)

            # Anti-downgrade check refuses --mode observe against allow_observe_mode=false. Exit code 2 alone also
            # covers usage errors and unreadable policies, so require the refusal message and no ledger.
            self.assertEqual(res.downgrade_exit_code, 2)
            self.assertIn(OBSERVE_REFUSAL_MESSAGE, res.downgrade_stderr)
            self.assertFalse(res.downgrade_ledger_created)
            self.assertTrue(res.downgrade_refused)

            # Enforce stage blocks .env (-32000) and severs session on canary exfiltration (-32099, exit 78).
            self.assertEqual(res.enforce_exit_code, AAD_EXIT_CODE)
            self.assertEqual(res.enforce_turn_responses["turn2_read_env"]["error"]["code"], JSONRPC_POLICY_VIOLATION)
            self.assertEqual(
                res.enforce_turn_responses["turn3_post_webhook"]["error"]["code"],
                JSONRPC_AAD_CONTAINMENT_SEVERED,
            )
            enf_rep = res.enforce_report
            self.assertTrue(enf_rep.chain_valid)
            self.assertEqual(enf_rep.status, "AAD_CONTAINED")
            self.assertEqual(len(enf_rep.sessions), 1)
            self.assertEqual(enf_rep.sessions[0].enforcement_mode, "enforce")

            enf_md = res.enforce_markdown_path.read_text(encoding="utf-8")
            self.assertIn("# Mellyn Incident Reconstruction (AAD_CONTAINED)", enf_md)
            self.assertIn("**Mode**: enforce", enf_md)

            out = io.StringIO()
            cli_dir = Path(tmp) / "cli-run"
            with redirect_stdout(out):
                rc = workflow_module.main(["--output-dir", str(cli_dir)])
            self.assertEqual(rc, 0)
            stdout_text = out.getvalue()
            self.assertIn("=== Mellyn Observe-Mode Red-Team Workflow ===", stdout_text)
            self.assertIn("=== Observe Timeline (mellyn-ir) ===", stdout_text)
            self.assertIn("=== Enforce Timeline (mellyn-ir) ===", stdout_text)

    def test_a_proxy_that_never_replies_fails_fast_instead_of_hanging(self) -> None:
        # Stands in for a proxy regression that swallows a response: `json.tool` reads stdin until EOF and
        # writes nothing before then, so every request goes unanswered.
        silent = subprocess.Popen(  # noqa: S603 - fixed local python subprocess
            [sys.executable, "-m", "json.tool"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(silent.wait, 5)
        self.addCleanup(silent.kill)
        replies: queue.Queue[str | None] = queue.Queue()
        threading.Thread(target=workflow_module._pump_lines, args=(silent.stdout, replies), daemon=True).start()

        original_timeout = workflow_module.REPLY_TIMEOUT_SECONDS
        workflow_module.REPLY_TIMEOUT_SECONDS = 0.5
        self.addCleanup(setattr, workflow_module, "REPLY_TIMEOUT_SECONDS", original_timeout)
        # Run the read on a thread so that, if the timeout ever regresses, this test fails instead of hanging CI.
        outcome: list[BaseException | None] = []

        def attempt() -> None:
            try:
                _send_and_read(silent, replies, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
                outcome.append(None)
            except BaseException as exc:  # noqa: BLE001 - recorded and asserted on below
                outcome.append(exc)

        reader = threading.Thread(target=attempt, daemon=True)
        reader.start()
        reader.join(timeout=5)
        self.assertFalse(reader.is_alive(), "_send_and_read kept waiting on a proxy that never replies")
        self.assertIsInstance(outcome[0], TimeoutError)
