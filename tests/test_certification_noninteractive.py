"""Adversarial process-boundary tests for unattended certification."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "certify-clean.sh"
PROMPT_FRAGMENTS = ("password:", "enter password", "press enter", "[y/n]", "[yes/no]")


class CertificationNonInteractiveTests(unittest.TestCase):
    def assert_no_prompt(self, completed: subprocess.CompletedProcess[str]) -> None:
        transcript = (completed.stdout + completed.stderr).lower()
        for fragment in PROMPT_FRAGMENTS:
            self.assertNotIn(fragment, transcript)

    def test_entrypoint_finishes_with_closed_stdin_without_prompting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            guard = Path(temporary_directory) / "guard"
            token = "private-recursion-token"
            guard.write_text(token, encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "__TRANSITVPN_CERTIFICATION_GUARD": str(guard),
                    "__TRANSITVPN_CERTIFICATION_TOKEN": token,
                }
            )

            completed = subprocess.run(
                [str(RUNNER)],
                cwd=PROJECT_ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("All acceptance checks passed.", completed.stdout)
        self.assert_no_prompt(completed)

    def test_missing_required_input_fails_without_prompt_or_credential_disclosure(self) -> None:
        credential = "credential-sentinel-do-not-print"
        with tempfile.TemporaryDirectory() as temporary_directory:
            isolated_root = Path(temporary_directory)
            scripts = isolated_root / "scripts"
            scripts.mkdir()
            (isolated_root / "tests").mkdir()
            isolated_runner = scripts / RUNNER.name
            shutil.copy2(RUNNER, isolated_runner)
            env = os.environ.copy()
            env["PIP_INDEX_URL"] = f"https://user:{credential}@packages.example.invalid/simple"

            completed = subprocess.run(
                [str(isolated_runner)],
                cwd=isolated_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
                check=False,
            )

        transcript = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 2, transcript)
        self.assertIn("Certification input is missing or unreadable", completed.stderr)
        self.assertNotIn(credential, transcript)
        self.assert_no_prompt(completed)


if __name__ == "__main__":
    unittest.main()
