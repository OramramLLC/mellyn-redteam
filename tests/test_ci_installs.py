"""CI installs nothing unpinned: every pip install is hash-locked; the editable core builds with the locked backend."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "redteam-ci.yml"
BUILD_LOCK = REPO_ROOT / "deploy" / "requirements-ci-build.lock"


def _pip_installs(text: str) -> list[str]:
    active = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    return re.findall(r"pip\s+install[^\n]*", active)


class TestCiInstallsArePinned(unittest.TestCase):
    def test_every_pip_install_is_hash_locked_or_a_no_build_isolation_editable_core(self) -> None:
        installs = _pip_installs(WORKFLOW.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(installs), 4)
        for cmd in installs:
            with self.subTest(cmd=cmd):
                self.assertIn("--no-deps", cmd)
                if " -e " in cmd:
                    # Without --no-build-isolation pip downloads the core's build backend (setuptools) unpinned and
                    # unhashed, outside every lock and the release cooldown.
                    self.assertIn("--no-build-isolation", cmd)
                    self.assertRegex(cmd, r"-e \./core\b")
                else:
                    self.assertIn("--require-hashes", cmd)
                    self.assertRegex(cmd, r'-r (\S*requirements-ci-(tests|build|lint)\.lock|"\$lock")')

    def test_the_lint_lock_variable_points_only_at_lint_locks(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        assignments = re.findall(r'lock="([^"]+)"', text)
        self.assertTrue(assignments)
        for path in assignments:
            with self.subTest(path=path):
                self.assertRegex(path, r"^(baseline|candidate)/deploy/requirements-ci-lint\.lock$")

    def test_build_lock_is_installed_before_the_editable_core(self) -> None:
        installs = _pip_installs(WORKFLOW.read_text(encoding="utf-8"))
        build = next(i for i, cmd in enumerate(installs) if "requirements-ci-build.lock" in cmd)
        editable = next(i for i, cmd in enumerate(installs) if " -e " in cmd)
        self.assertLess(build, editable)

    def test_build_lock_pins_setuptools_with_hashes(self) -> None:
        text = re.sub(r"(?m)^\s*#.*\n", "", BUILD_LOCK.read_text(encoding="utf-8")).strip()
        entries = re.split(r"\n(?=[A-Za-z0-9])", text)
        self.assertEqual([e.split("==", 1)[0] for e in entries], ["setuptools"])
        self.assertRegex(entries[0], r"^setuptools==\d+(\.\d+)+ ")
        self.assertGreaterEqual(len(re.findall(r"--hash=sha256:[0-9a-f]{64}", entries[0])), 1)
        self.assertNotRegex(text, r"--(index-url|extra-index-url|find-links|trusted-host)\b")


if __name__ == "__main__":
    unittest.main()
