"""Adversarial contract tests for certification's pre-collection install boundary."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "certify-clean.sh"


def shell_logical_lines(source: str) -> list[str]:
    """Join continuations and discard comments for command-level inspection."""
    logical_lines: list[str] = []
    continued = ""
    for physical_line in source.splitlines():
        stripped = physical_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued += (" " if continued else "") + stripped.rstrip("\\").rstrip()
        if stripped.endswith("\\"):
            continue
        logical_lines.append(continued)
        continued = ""
    if continued:
        logical_lines.append(continued)
    return logical_lines


class CertificationInstallBoundaryTests(unittest.TestCase):
    def test_only_exact_lockfile_is_installed_before_collection(self) -> None:
        lines = shell_logical_lines(RUNNER.read_text(encoding="utf-8"))
        collection_index = next(
            index
            for index, line in enumerate(lines)
            if re.search(r'"\$venv/bin/python"\s+-m\s+pytest\s+--collect-only\b', line)
        )
        before_collection = lines[:collection_index]

        venv_index = next(
            index
            for index, line in enumerate(before_collection)
            if line == 'python3 -m venv "$venv" </dev/null'
        )
        install_commands = [
            (index, line)
            for index, line in enumerate(before_collection)
            if re.search(r'(?:-m\s+pip|/pip[0-9.]*"?|\buv\s+pip)\s+install\b', line)
        ]
        self.assertEqual(
            len(install_commands),
            1,
            f"expected exactly one installer invocation before collection: {install_commands}",
        )

        install_index, install_line = install_commands[0]
        self.assertLess(venv_index, install_index, "dependencies were installed before venv creation")
        self.assertLess(install_index, collection_index)
        self.assertEqual(
            next(line for line in before_collection if line.startswith("lock_file=")),
            'lock_file="$project_root/requirements-certification.lock"',
        )

        tokens = shlex.split(install_line)
        install_token = tokens.index("install")
        install_arguments: list[str] = []
        for token in tokens[install_token + 1 :]:
            if token.startswith(">") or token.startswith("2>") or token == "then":
                break
            install_arguments.append(token.rstrip(";"))

        self.assertEqual(
            install_arguments,
            [
                "--disable-pip-version-check",
                "--no-input",
                "--quiet",
                "--requirement",
                "$lock_file",
            ],
            "pre-collection pip may consume only requirements-certification.lock; "
            "editable, project, bare-package, and alternate requirement sources are forbidden",
        )


if __name__ == "__main__":
    unittest.main()
