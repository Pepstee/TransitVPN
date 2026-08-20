"""Independent black-box contract for the root certification declaration."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ACCEPTANCE = PROJECT_ROOT / "acceptance"
STDIN_SENTINEL = "orchestrator-stdin-must-remain-unread"


class AcceptanceOneToolStdinTests(unittest.TestCase):
    def test_both_gate_contexts_allow_one_tool_and_preserve_stdin(self) -> None:
        declarations = [
            line.strip()
            for line in ACCEPTANCE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(len(declarations), 1, declarations)

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary = Path(temporary_directory)
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            guard = temporary / "recursion-guard"
            token = "test-owned-private-guard"
            guard.write_text(token, encoding="utf-8")

            for tool, real_tool in (("bash", "/bin/bash"), ("dirname", "/usr/bin/dirname")):
                wrapper = fake_bin / tool
                wrapper.write_text(
                    "#!/bin/sh\n"
                    f"printf '%s\\n' '{tool}' >> \"$TOOL_INVOCATION_LOG\"\n"
                    f"exec {real_tool} \"$@\"\n",
                    encoding="utf-8",
                )
                wrapper.chmod(0o755)

            contexts = (
                ("extracted", ["/bin/bash", "-c", declarations[0]], PROJECT_ROOT),
                ("direct", ["/bin/bash", str(ACCEPTANCE)], temporary),
            )
            for name, command, cwd in contexts:
                with self.subTest(context=name):
                    invocation_log = temporary / f"{name}-tool-invocations"
                    env = os.environ.copy()
                    env.update(
                        {
                            "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                            "TOOL_INVOCATION_LOG": str(invocation_log),
                            "__TRANSITVPN_CERTIFICATION_GUARD": str(guard),
                            "__TRANSITVPN_CERTIFICATION_TOKEN": token,
                        }
                    )
                    read_fd, write_fd = os.pipe()
                    try:
                        supplied = f"{STDIN_SENTINEL}-{name}\n".encode()
                        os.write(write_fd, supplied)
                        os.close(write_fd)
                        write_fd = -1
                        completed = subprocess.run(
                            command,
                            cwd=cwd,
                            env=env,
                            stdin=read_fd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            timeout=5,
                            check=False,
                        )
                        remaining = os.read(read_fd, len(supplied) + 1)
                    finally:
                        os.close(read_fd)
                        if write_fd >= 0:
                            os.close(write_fd)

                    invocations = invocation_log.read_text(encoding="utf-8").splitlines()
                    transcript = completed.stdout + completed.stderr
                    self.assertEqual(completed.returncode, 0, transcript)
                    self.assertLessEqual(len(invocations), 1, invocations)
                    self.assertEqual(invocations, ["bash"])
                    self.assertEqual(remaining, supplied, "acceptance consumed caller stdin")
                    self.assertNotIn(STDIN_SENTINEL, transcript)


if __name__ == "__main__":
    unittest.main()
