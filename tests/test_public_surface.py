"""Contract tests ensuring `PUBLIC_SURFACE.md` stays complete and no core internals are copied or declared."""

from __future__ import annotations

import ast
import collections
import re
import tomllib
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PUBLIC_SURFACE = REPO_ROOT / "PUBLIC_SURFACE.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"
EVAL_README = REPO_ROOT / "examples" / "adversarial_eval" / "README.md"

_IMPORT_ROW_RE = re.compile(r"^\|\s*`(mellyn(?:\.[A-Za-z0-9_]+)*)`\s*\|\s*([^|]+)\|")
_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_CLI_ROW_RE = re.compile(r"^\|\s*`(mellyn(?:-[a-z]+)?)`\s*\|")


def _is_core_module(mod: str) -> bool:
    return mod == "mellyn" or mod.startswith("mellyn.")


def _collect_all_imports() -> dict[str, set[str]]:
    imports: dict[str, set[str]] = collections.defaultdict(set)
    for path in sorted(REPO_ROOT.rglob("*.py")):
        rel_parts = path.relative_to(REPO_ROOT).parts
        if any(part.startswith(".") or part == "core" for part in rel_parts):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[node.module].add(alias.name)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.name].add(alias.name)
    return dict(imports)


def _collect_actual_core_imports() -> dict[str, set[str]]:
    return {mod: syms for mod, syms in _collect_all_imports().items() if _is_core_module(mod)}


def _collect_documented_core_imports() -> dict[str, set[str]]:
    documented: dict[str, set[str]] = collections.defaultdict(set)
    for line in PUBLIC_SURFACE.read_text(encoding="utf-8").splitlines():
        m = _IMPORT_ROW_RE.match(line)
        if not m:
            continue
        module_name, symbols_col = m.group(1), m.group(2)
        for sym in _BACKTICK_RE.findall(symbols_col):
            documented[module_name].add(sym)
    return dict(documented)


def _collect_documented_clis() -> set[str]:
    clis: set[str] = set()
    for line in PUBLIC_SURFACE.read_text(encoding="utf-8").splitlines():
        m = _CLI_ROW_RE.match(line)
        if m:
            clis.add(m.group(1))
    return clis


class TestPublicSurfaceContract(unittest.TestCase):
    def test_every_core_import_is_documented_without_drift(self) -> None:
        actual = _collect_actual_core_imports()
        documented = _collect_documented_core_imports()
        self.assertEqual(
            documented,
            actual,
            "PUBLIC_SURFACE.md import tables must match the exact `mellyn.*` AST imports.",
        )

    def test_all_five_core_cli_scripts_are_documented(self) -> None:
        self.assertEqual(
            _collect_documented_clis(),
            {"mellyn", "mellyn-airlock", "mellyn-pin", "mellyn-ir", "mellyn-bench"},
        )

    def test_forbidden_core_or_guardrail_internals_not_copied_or_imported(self) -> None:
        bench_matches = [
            p
            for p in REPO_ROOT.rglob("bench.py")
            if not any(part.startswith(".") or part == "core" for part in p.parts)
        ]
        self.assertEqual(bench_matches, [], "Do not copy bench.py into mellyn-redteam; invoke mellyn-bench CLI.")

        all_imports = _collect_all_imports()
        legacy_pkg = "mcp_" + "airlock"
        forbidden_prefixes = (
            legacy_pkg,
            "mellyn.egress." + "bench",
            "mellyn." + "viewer_server",
            "sync_" + "agent_rules",
            "verify_" + "dependencies",
        )
        for prefix in forbidden_prefixes:
            for mod in all_imports:
                self.assertFalse(
                    mod == prefix or mod.startswith(prefix + "."),
                    f"Forbidden or removed import module referenced: {mod}",
                )
        self.assertNotIn("bench", all_imports.get("mellyn.egress", set()))

    def test_pyproject_declares_no_mellyn_security_or_non_registry_dependencies(self) -> None:
        raw = PYPROJECT.read_text(encoding="utf-8")
        data = tomllib.loads(raw)
        project = data.get("project", {})
        self.assertEqual(project.get("dependencies", []), [])
        self.assertEqual(project.get("optional-dependencies", {}), {})
        self.assertNotIn("mellyn" + "-security", raw)
        self.assertNotIn("git+", raw)

    def test_adversarial_readme_retains_what_this_does_not_cover_section(self) -> None:
        text = EVAL_README.read_text(encoding="utf-8")
        self.assertIn("## What this does not cover", text)
        self.assertIn("Canary and secret detection compare text against known encodings", text)


if __name__ == "__main__":
    unittest.main()
