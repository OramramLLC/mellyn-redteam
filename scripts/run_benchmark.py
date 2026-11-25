#!/usr/bin/env python3
"""
Invoke `mellyn-bench --json` via subprocess and validate deterministic accuracy/latency gates.

Calls the installed `mellyn-bench` CLI directly rather than copying or importing `mcp_airlock.egress.bench`.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def resolve_bench_cli(python_executable: str = sys.executable) -> str:
    """Resolve `mellyn-bench` sibling binary next to Python or on PATH; fail closed if missing."""
    scripts_dir = Path(python_executable).resolve().parent
    for name in ("mellyn-bench.exe", "mellyn-bench"):
        candidate = scripts_dir / name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("mellyn-bench")
    if found:
        return found
    raise FileNotFoundError("Could not locate `mellyn-bench` CLI; install mellyn-security (`pip install -e ../V1`).")


def run_mellyn_bench(*, iterations: int = 10, python_executable: str = sys.executable) -> tuple[int, dict[str, Any]]:
    """Run `mellyn-bench --iterations <N> --json` as a subprocess and validate metrics."""
    bench_cli = resolve_bench_cli(python_executable)
    proc = subprocess.run(  # noqa: S603 - explicit resolved CLI path, no shell
        [bench_cli, "--iterations", str(iterations), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    if not proc.stdout.strip():
        raise RuntimeError(f"mellyn-bench emitted no stdout (exit={proc.returncode}): {proc.stderr.strip()}")
    report = json.loads(proc.stdout)
    if not isinstance(report, dict):
        raise ValueError("mellyn-bench JSON output must be an object.")
    return proc.returncode, report


def report_meets_gates(report: dict[str, Any]) -> bool:
    """Return True iff the benchmark report passed with zero FP/FN and finite latency."""
    p50 = report.get("p50_us_per_kb")
    p99 = report.get("p99_us_per_kb")
    return (
        report.get("passed") is True
        and report.get("canary_recall") == 1.0
        and report.get("false_positives") == 0
        and report.get("false_negatives") == 0
        and isinstance(p50, (int, float))
        and math.isfinite(p50)
        and p50 >= 0.0
        and isinstance(p99, (int, float))
        and math.isfinite(p99)
        and p99 >= 0.0
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Execute and validate `mellyn-bench --json` via subprocess.")
    parser.add_argument("--iterations", type=int, default=10, help="Iterations passed to `mellyn-bench`.")
    parser.add_argument("--json", action="store_true", help="Emit parsed `mellyn-bench` JSON report to stdout.")
    args = parser.parse_args(argv)

    try:
        rc, report = run_mellyn_bench(iterations=args.iterations)
    except (FileNotFoundError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        sys.stderr.write(f"run_benchmark: {exc}\n")
        return 2

    ok = rc == 0 and report_meets_gates(report)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        verdict = "PASS" if ok else "FAIL"
        print(
            f"mellyn-bench ({verdict}): samples={report.get('total_samples')} "
            f"precision={report.get('precision')} recall={report.get('recall')} "
            f"canary_recall={report.get('canary_recall')} p50={report.get('p50_us_per_kb')}us/KB"
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
