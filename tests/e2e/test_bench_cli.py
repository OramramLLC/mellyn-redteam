"""E2E regression tests verifying `mellyn-bench --json` CLI execution without copying `bench.py`."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"
for _p in (REPO_ROOT, SCRIPTS_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import run_benchmark  # noqa: E402


class TestMellynBenchCliIntegration(unittest.TestCase):
    def test_mellyn_bench_json_cli_passes(self) -> None:
        rc, report = run_benchmark.run_mellyn_bench(iterations=2)
        self.assertEqual(rc, 0)
        self.assertTrue(run_benchmark.report_meets_gates(report), report)
        self.assertGreaterEqual(report["total_samples"], 1)

        out = io.StringIO()
        with redirect_stdout(out):
            cli_rc = run_benchmark.main(["--iterations", "1", "--json"])
        self.assertEqual(cli_rc, 0)
        parsed = json.loads(out.getvalue())
        self.assertTrue(parsed["passed"])
