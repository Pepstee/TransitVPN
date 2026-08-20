"""Adversarial black-box coverage for the bounded credential gate."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "certify-clean.sh"
SCANNER = PROJECT_ROOT / "scripts" / "scan-credentials.py"


class CleanCertificationCredentialGateTests(unittest.TestCase):
    def run_gate(self, *, reject_credentials: bool = False) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        log = root / "calls"

        python = fake_bin / "python3"
        python.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                printf 'python3' >> "$GATE_LOG"
                for arg in "$@"; do printf '|%s' "$arg" >> "$GATE_LOG"; done
                if IFS= read -r value; then
                    printf '|STDIN=CONSUMED:%s\n' "$value" >> "$GATE_LOG"
                else
                    printf '|STDIN=EOF\n' >> "$GATE_LOG"
                fi
                if [ "$1" = "$GATE_SCANNER" ] && [ "${REJECT_CREDENTIALS-0}" = 1 ]; then
                    printf '%s\n' 'negative-control.txt: password-token' >&2
                    exit 23
                fi
                if [ "$1" = -m ] && [ "$2" = venv ]; then
                    /bin/mkdir -p "$3/bin"
                    /bin/cp "$0" "$3/bin/python"
                fi
                exit 0
                """
            ),
            encoding="utf-8",
        )
        python.chmod(0o755)

        wrappers = {
            "git": "exit 0",
            "cmp": 'exec /usr/bin/cmp "$@"',
            "rm": 'exec /bin/rm "$@"',
        }
        for name, action in wrappers.items():
            wrapper = fake_bin / name
            wrapper.write_text(
                textwrap.dedent(
                    f"""\
                    #!/bin/sh
                    printf '{name}' >> "$GATE_LOG"
                    for arg in "$@"; do printf '|%s' "$arg" >> "$GATE_LOG"; done
                    if IFS= read -r value; then
                        printf '|STDIN=CONSUMED:%s\n' "$value" >> "$GATE_LOG"
                    else
                        printf '|STDIN=EOF\n' >> "$GATE_LOG"
                    fi
                    {action}
                    """
                ),
                encoding="utf-8",
            )
            wrapper.chmod(0o755)

        mktemp = fake_bin / "mktemp"
        mktemp.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                printf 'mktemp|%s' "$1" >> "$GATE_LOG"
                if IFS= read -r value; then
                    printf '|STDIN=CONSUMED:%s\n' "$value" >> "$GATE_LOG"
                else
                    printf '|STDIN=EOF\n' >> "$GATE_LOG"
                fi
                created="$TMPDIR/gate-root"
                /bin/mkdir "$created"
                printf '%s\n' "$created"
                """
            ),
            encoding="utf-8",
        )
        mktemp.chmod(0o755)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "TMPDIR": str(root),
                "GATE_LOG": str(log),
                "GATE_SCANNER": str(SCANNER),
                "REJECT_CREDENTIALS": "1" if reject_credentials else "0",
            }
        )
        command = [
            "/bin/bash",
            "-c",
            '"$1"; status=$?; IFS= read -r remaining; '
            "printf 'CALLER_STDIN=%s\\n' \"$remaining\"; exit \"$status\"",
            "credential-gate-probe",
            str(RUNNER),
        ]
        completed = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            input="orchestrator-message-must-remain-unread\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines()
        return completed, calls

    def test_executable_credential_negative_control_fails_gate_first(self) -> None:
        completed, calls = self.run_gate(reject_credentials=True)

        self.assertEqual(23, completed.returncode, completed.stdout + completed.stderr)
        self.assertEqual(1, len(calls), calls)
        self.assertTrue(calls[0].startswith(f"python3|{SCANNER}"), calls)
        self.assertTrue(calls[0].endswith("|STDIN=EOF"), calls)
        self.assertIn("negative-control.txt: password-token", completed.stderr)
        self.assertNotIn("All acceptance checks passed.", completed.stdout)

    def test_successful_full_gate_is_twelve_calls_and_never_reads_stdin(self) -> None:
        completed, calls = self.run_gate()
        transcript = "\n".join(calls) + completed.stdout + completed.stderr

        self.assertEqual(0, completed.returncode, transcript)
        self.assertEqual(12, len(calls), calls)
        self.assertEqual(1, sum(line.startswith(f"python3|{SCANNER}") for line in calls), calls)
        self.assertTrue(all(line.endswith("|STDIN=EOF") for line in calls), calls)
        self.assertNotIn("STDIN=CONSUMED", transcript)
        self.assertIn("CALLER_STDIN=orchestrator-message-must-remain-unread", completed.stdout)
        self.assertIn("All acceptance checks passed.", completed.stdout)


if __name__ == "__main__":
    unittest.main()
