"""Independent contract tests for the acceptance demo declaration."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
DECLARATION = ROOT / "acceptance"
DEMO = ROOT / "scripts" / "acceptance-demo.sh"
SENTINEL = b"untrusted-orchestrator-input-must-not-be-read\n"
TOOL_BUDGET = 18


def executable_lines() -> list[str]:
    return [
        line.strip()
        for line in DECLARATION.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class AcceptanceDemoBudgetIsolationTest(unittest.TestCase):
    def test_declaration_is_data_and_demo_is_bounded_and_detached(self) -> None:
        commands = executable_lines()
        self.assertEqual(len(commands), 1, "acceptance must declare one independent command")
        command = commands[0]

        # The declaration points at a separate, substantive demo; it is not a
        # disguised inline shell/Python program or a dependency on shell $0.
        self.assertTrue(DEMO.is_file())
        demo_lines = [
            line for line in DEMO.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertGreater(len(demo_lines), 3, "the multi-line demo belongs in its own file")
        self.assertIn("scripts/acceptance-demo.sh", command)
        self.assertIn("BASH_SOURCE[0]", command)
        self.assertNotRegex(command, r"\$\{?0(?:\}|\b)")
        self.assertNotRegex(command, r"(?:^|\s)(?:bash|sh|python(?:3)?)?\s*-[^\s]*c\b")
        self.assertNotRegex(command, r"<<-?\s*['\"]?\w+")
        self.assertNotRegex(command, r"(?:^|[;&|])\s*(?:source|eval|\.)\s")
        self.assertNotRegex(command, r"(?:&&|\|\||;|(?<![<>])\|(?![|]))")

        self._exercise(["/bin/bash", "-c", command], ROOT, "extracted command")
        with tempfile.TemporaryDirectory() as unrelated:
            self._exercise(
                ["/bin/bash", str(DECLARATION)],
                Path(unrelated),
                "direct declaration from unrelated cwd",
            )

    def _exercise(self, argv: list[str], cwd: Path, context: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            area = Path(temporary)
            fake_bin = area / "bin"
            fake_bin.mkdir()
            log = area / "tool-calls"
            self._write_probe(fake_bin / "bash", "/bin/bash")
            self._write_probe(fake_bin / "python3", str(Path(sys.executable).resolve()))

            env = os.environ.copy()
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
            env["ACCEPTANCE_PROBE_LOG"] = str(log)
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, SENTINEL)
                os.close(write_fd)
                write_fd = -1
                completed = subprocess.run(
                    argv,
                    cwd=cwd,
                    env=env,
                    stdin=read_fd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=15,
                    check=False,
                )
                unread = os.read(read_fd, len(SENTINEL) + 1)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)

            calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            transcript = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 0, f"{context}: {transcript}")
            self.assertIn("All acceptance checks passed.", completed.stdout)
            self.assertTrue(calls, f"{context}: no demo tools were observed")
            self.assertLessEqual(len(calls), TOOL_BUDGET, f"{context}: {calls}")
            self.assertTrue(all(call.endswith(" STDIN_EOF") for call in calls), calls)
            self.assertEqual(unread, SENTINEL, f"{context}: acceptance drained caller stdin")
            self.assertNotIn(SENTINEL.decode().strip(), transcript)

    @staticmethod
    def _write_probe(path: Path, real_program: str) -> None:
        path.write_text(
            "#!/bin/sh\n"
            "if IFS= read -r stolen; then\n"
            "  printf '%s STDIN_READ <%s>\\n' \"$0\" \"$stolen\" >> \"$ACCEPTANCE_PROBE_LOG\"\n"
            "else\n"
            "  printf '%s STDIN_EOF\\n' \"$0\" >> \"$ACCEPTANCE_PROBE_LOG\"\n"
            "fi\n"
            f"exec {shlex.quote(real_program)} \"$@\"\n",
            encoding="utf-8",
        )
        path.chmod(0o755)


if __name__ == "__main__":
    unittest.main()
