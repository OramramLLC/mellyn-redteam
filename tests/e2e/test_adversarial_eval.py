"""E2E regression test running the 25-scenario adversarial red-team scorecard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from examples.adversarial_eval.run_redteam import run_all_attacks  # noqa: E402


class TestAdversarialRedTeamSuite(unittest.TestCase):
    def test_all_25_adversarial_scenarios_pass(self) -> None:
        outcomes = run_all_attacks()
        self.assertEqual(len(outcomes), 25)
        for outcome in outcomes:
            with self.subTest(case_id=outcome.case_id):
                self.assertTrue(outcome.passed, f"{outcome.case_id} failed: {outcome.observed}")
