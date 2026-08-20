"""Independent contract tests for the clean-environment certification runner."""

from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "certify-clean.sh"


class CleanCertificationRunnerTests(unittest.TestCase):
    def test_runner_has_an_executable_fail_fast_shell_contract(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        self.assertEqual(source.splitlines()[0], "#!/usr/bin/env bash")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode) & 0o111, 0o111)
        self.assertRegex(source, r"(?m)^set -euo pipefail$")
        self.assertRegex(source, r"(?m)^trap cleanup EXIT HUP INT TERM$")
        self.assertRegex(source, r'(?m)^\s*rm -rf -- "\$temporary_root"$')

    def test_runner_uses_no_credential_arguments_or_embedded_fixtures(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")
        forbidden = (
            r"https?://[^\s'\"]+@",
            r"(?i)--(?:password|token|client-secret|cert|key)(?:=|\s)",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            r"(?i)(?:password|access_token|api_key|client_secret)\s*=[^=]",
        )

        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertIsNone(re.search(pattern, source))
        self.assertIn(">/dev/null 2>&1", source)

    def test_execution_is_isolated_deterministic_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as sandbox_name:
            sandbox = Path(sandbox_name)
            fake_bin = sandbox / "bin"
            fake_bin.mkdir()
            calls = sandbox / "calls"
            created_root = sandbox / "created-root"
            fake_python = fake_bin / "python3"
            fake_python.write_text(
                textwrap.dedent(
                    """\
                    #!/bin/sh
                    printf 'CALL' >> "$CERT_CALLS"
                    for arg in "$@"; do printf '|%s' "$arg" >> "$CERT_CALLS"; done
                    printf '|HASH=%s|PLUGINS=%s|ACTIVE=%s|PYTHONPATH=%s|ADDOPTS=%s\\n' \\
                        "${PYTHONHASHSEED-}" "${PYTEST_DISABLE_PLUGIN_AUTOLOAD-}" \\
                        "${TRANSITVPN_CERTIFICATION_ACTIVE-}" "${PYTHONPATH-}" \\
                        "${PYTEST_ADDOPTS-}" >> "$CERT_CALLS"
                    if [ "$1" = -m ] && [ "$2" = venv ]; then
                        mkdir -p "$3/bin"
                        cp "$0" "$3/bin/python"
                        printf '%s\\n' "$(dirname "$3")" > "$CERT_CREATED_ROOT"
                    fi
                    exit 0
                    """
                ),
                encoding="utf-8",
            )
            fake_python.chmod(0o755)
            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                    "TMPDIR": str(sandbox),
                    "CERT_CALLS": str(calls),
                    "CERT_CREATED_ROOT": str(created_root),
                    "PYTHONPATH": "/hostile/python/path",
                    "PYTEST_ADDOPTS": "--capture=no --maxfail=1",
                }
            )

            completed = subprocess.run(
                [str(RUNNER)],
                cwd=sandbox,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            temporary_root = Path(created_root.read_text(encoding="utf-8").strip())
            self.assertFalse(temporary_root.exists(), "EXIT trap left its temporary tree behind")

            recorded = calls.read_text(encoding="utf-8").splitlines()
            common_env = "|HASH=0|PLUGINS=1|ACTIVE=1|PYTHONPATH=|ADDOPTS="
            venv = temporary_root / "venv"
            expected = [
                f"CALL|-m|venv|{venv}{common_env}",
                f"CALL|-m|pip|install|--disable-pip-version-check|--quiet|{PROJECT_ROOT}[test]{common_env}",
                f"CALL|-m|pytest|--collect-only|-q{common_env}",
                f"CALL|-m|pytest|-q{common_env}",
            ]
            self.assertEqual(recorded, expected)
            self.assertEqual(
                completed.stdout.splitlines(),
                [
                    "Collecting tests in clean environment...",
                    "Running tests in clean environment...",
                    "All acceptance checks passed.",
                ],
            )


if __name__ == "__main__":
    unittest.main()
