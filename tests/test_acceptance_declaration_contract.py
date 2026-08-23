"""Adversarial tests for the root acceptance declaration-as-data contract."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = PROJECT_ROOT / "acceptance"
DEMO = PROJECT_ROOT / "scripts" / "acceptance-demo.sh"


def declarations() -> list[str]:
    return [
        line.strip()
        for line in ACCEPTANCE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.update(
        {
            "CI": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "SSH_ASKPASS": "/bin/false",
            "SSH_ASKPASS_REQUIRE": "force",
        }
    )
    return subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
        check=False,
    )


class AcceptanceDeclarationContractTests(unittest.TestCase):
    def assert_successful_and_safe(self, result: subprocess.CompletedProcess[str]) -> None:
        transcript = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, transcript)
        self.assertIn("All acceptance checks passed.", result.stdout)
        self.assertNotRegex(transcript, r"(?i)password\s*[:=]")
        self.assertNotRegex(transcript, r"(?i)(?:private[_ -]?key|secret|token)\s*[:=]")
        self.assertNotRegex(
            transcript,
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
        )
        self.assertNotIn("BEGIN PRIVATE KEY", transcript)

    def test_every_declaration_executes_independently_from_project_root(self) -> None:
        commands = declarations()
        self.assertTrue(commands, "acceptance contains no declarations")
        for command in commands:
            with self.subTest(command=command):
                self.assert_successful_and_safe(run(["/bin/bash", "-c", command], cwd=PROJECT_ROOT))

    def test_declaration_is_directly_invocable_from_unrelated_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = run(["/bin/bash", str(ACCEPTANCE)], cwd=Path(directory))
        self.assert_successful_and_safe(result)

    def test_declaration_is_data_not_an_embedded_program(self) -> None:
        commands = declarations()
        self.assertEqual(commands, [commands[0]], "each declaration must be a standalone command")
        physical_commands = [
            line
            for line in ACCEPTANCE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(physical_commands, commands, "declaration must be one physical command line")
        command = commands[0]
        self.assertRegex(command, r"^bash\s+")
        self.assertIn("scripts/acceptance-demo.sh", command)
        self.assertIn("BASH_SOURCE[0]", command)
        self.assertNotRegex(command, r"(?:^|\s)(?:bash|sh|python(?:3)?)?\s*-(?:[a-zA-Z]*c)\b")
        self.assertNotRegex(command, r"<<-?\s*['\"]?\w+")
        self.assertNotRegex(command, r"(?:^|[\s;|&])(?:eval|source|\.)\s")
        self.assertNotRegex(command, r"\$\{?0(?:\}|\b)")
        self.assertNotRegex(command, r"(?:;|&&|\|\||(?<![<>])\|(?![&]))")

    def test_acceptance_path_has_no_credential_fixture(self) -> None:
        source = ACCEPTANCE.read_text(encoding="utf-8") + "\n" + DEMO.read_text(encoding="utf-8")
        self.assertNotRegex(source, r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F-]{23}\b")
        self.assertNotRegex(source, r"(?i)(?:password|private[_ -]?key|secret|token)\s*[:=]\s*['\"][^'\"]+")
        self.assertNotIn("BEGIN PRIVATE KEY", source)
        self.assertNotRegex(source, r"\bgenerate_keys\s*\(")


if __name__ == "__main__":
    unittest.main()
