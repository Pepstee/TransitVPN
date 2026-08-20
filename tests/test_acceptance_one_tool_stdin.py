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
    def test_enforced_harness_allows_one_tool_and_preserves_stdin(self) -> None:
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
            invocation_log = temporary / "tool-invocations"
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

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "TOOL_INVOCATION_LOG": str(invocation_log),
                    "__TRANSITVPN_CERTIFICATION_GUARD": str(guard),
                    "__TRANSITVPN_CERTIFICATION_TOKEN": token,
                }
            )
            harness = (
                f"{declarations[0]}\n"
                "status=$?\n"
                "if IFS= read -r remaining; then\n"
                "  printf 'HARNESS_STDIN=<%s>\\n' \"$remaining\"\n"
                "else\n"
                "  printf '%s\\n' 'Reading additional input from stdin...'\n"
                "fi\n"
                "exit \"$status\"\n"
            )
            completed = subprocess.run(
                ["/bin/bash", "-c", harness],
                cwd=PROJECT_ROOT,
                env=env,
                input=f"{STDIN_SENTINEL}\n",
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
            )

            invocations = invocation_log.read_text(encoding="utf-8").splitlines()

        transcript = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, transcript)
        self.assertLessEqual(len(invocations), 1, invocations)
        self.assertEqual(invocations, ["bash"])
        self.assertIn(f"HARNESS_STDIN=<{STDIN_SENTINEL}>", completed.stdout)
        self.assertNotIn("Reading additional input from stdin...", transcript)


if __name__ == "__main__":
    unittest.main()
