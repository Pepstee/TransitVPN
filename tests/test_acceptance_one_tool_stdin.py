"""Adversarial black-box tests for acceptance budget and stdin isolation."""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = PROJECT_ROOT / "acceptance"
MAX_TOOL_INVOCATIONS = 18
STDIN_SENTINEL = b"orchestrator-stdin-must-remain-unread\n"


def declarations() -> list[str]:
    return [
        line.strip()
        for line in ACCEPTANCE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


class AcceptanceBudgetStdinTests(unittest.TestCase):
    def _make_wrapper(self, path: Path, name: str, target: Path) -> None:
        # Each observable tool actively probes fd 0.  A correctly isolated demo
        # gives every probe EOF; an inherited pipe yields the sentinel and fails.
        path.write_text(
            "#!/bin/bash\n"
            "if IFS= read -r value; then\n"
            f"  printf 'CONSUMED {name} %s\\n' \"$value\" >> \"$ACCEPTANCE_TOOL_LOG\"\n"
            "else\n"
            f"  printf 'EOF {name}\\n' >> \"$ACCEPTANCE_TOOL_LOG\"\n"
            "fi\n"
            f"exec {shlex.quote(str(target))} \"$@\"\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    def _run(self, command: list[str], cwd: Path, label: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            log = root / "tools.log"
            self._make_wrapper(fake_bin / "bash", "bash", Path("/bin/bash"))
            self._make_wrapper(fake_bin / "python3", "python3", Path(sys.executable).resolve())

            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{environment['PATH']}",
                    "ACCEPTANCE_TOOL_LOG": str(log),
                }
            )
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, STDIN_SENTINEL)
                os.close(write_fd)
                write_fd = -1
                completed = subprocess.run(
                    command,
                    cwd=cwd,
                    env=environment,
                    stdin=read_fd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                )
                remaining = os.read(read_fd, len(STDIN_SENTINEL) + 1)
            finally:
                os.close(read_fd)
                if write_fd >= 0:
                    os.close(write_fd)

            events = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
            transcript = completed.stdout + completed.stderr
            self.assertEqual(completed.returncode, 0, f"{label}: {transcript}")
            self.assertTrue(events, f"{label}: no tool invocation was observed")
            self.assertLessEqual(len(events), MAX_TOOL_INVOCATIONS, f"{label}: {events}")
            self.assertTrue(
                all(event.startswith("EOF ") for event in events),
                f"{label}: a demo command inherited readable stdin: {events}",
            )
            self.assertEqual(remaining, STDIN_SENTINEL, f"{label}: caller stdin was drained")
            self.assertNotIn(STDIN_SENTINEL.decode().strip(), transcript)

    def test_extracted_commands_are_bounded_and_stdin_isolated(self) -> None:
        commands = declarations()
        self.assertTrue(commands, "acceptance has no executable declarations")
        for index, command in enumerate(commands):
            with self.subTest(index=index, command=command):
                self._run(["/bin/bash", "-c", command], PROJECT_ROOT, f"extracted[{index}]")

    def test_direct_declaration_is_bounded_and_stdin_isolated(self) -> None:
        first_line = ACCEPTANCE.read_text(encoding="utf-8").splitlines()[0]
        if not first_line.startswith("#!"):
            self.skipTest("acceptance does not declare direct-execution support")
        with tempfile.TemporaryDirectory() as unrelated:
            self._run(["/bin/bash", str(ACCEPTANCE)], Path(unrelated), "direct")


if __name__ == "__main__":
    unittest.main()
