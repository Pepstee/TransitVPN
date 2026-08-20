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
    def run_instrumented_runner(
        self, *, fail_install: bool = False, mutate_during_tests: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], list[str], Path]:
        sandbox_context = tempfile.TemporaryDirectory()
        self.addCleanup(sandbox_context.cleanup)
        sandbox = Path(sandbox_context.name)
        fake_bin = sandbox / "bin"
        fake_bin.mkdir()
        calls = sandbox / "calls"
        created_root = sandbox / "created-root"
        mutation_marker = sandbox / "pytest-mutated"

        fake_python = fake_bin / "python3"
        fake_python.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                printf 'CALL' >> "$CERT_CALLS"
                for arg in "$@"; do printf '|%s' "$arg" >> "$CERT_CALLS"; done
                printf '|ACTIVE=%s|CONSTRAINT=%s|PYTHONPATH=%s|ADDOPTS=%s\\n' \\
                    "${TRANSITVPN_CERTIFICATION_ACTIVE-}" "${PIP_CONSTRAINT-}" \\
                    "${PYTHONPATH-}" "${PYTEST_ADDOPTS-}" >> "$CERT_CALLS"
                if [ "$1" = -m ] && [ "$2" = venv ]; then
                    mkdir -p "$3/bin"
                    cp "$0" "$3/bin/python"
                    printf '%s\\n' "$(dirname "$3")" > "$CERT_CREATED_ROOT"
                elif [ "$1" = -m ] && [ "$2" = pip ] && [ "${CERT_FAIL_INSTALL-}" = 1 ]; then
                    printf '%s\\n' \\
                        'https://alice:super-secret@example.invalid/simple' \\
                        'token=installation-secret' >&2  # credential-scan: allow password-token
                    exit 19
                elif [ "$1" = -m ] && [ "$2" = pytest ] && \\
                     [ "$3" != --collect-only ] && [ "${CERT_MUTATE-}" = 1 ]; then
                    : > "$CERT_MUTATION_MARKER"
                fi
                exit 0
                """
            ),
            encoding="utf-8",
        )
        fake_python.chmod(0o755)

        fake_git = fake_bin / "git"
        fake_git.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                if [ -e "$CERT_MUTATION_MARKER" ]; then
                    printf '%s\\n' 'tracked state changed during pytest'
                fi
                """
            ),
            encoding="utf-8",
        )
        fake_git.chmod(0o755)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "TMPDIR": str(sandbox),
                "CERT_CALLS": str(calls),
                "CERT_CREATED_ROOT": str(created_root),
                "CERT_FAIL_INSTALL": "1" if fail_install else "0",
                "CERT_MUTATE": "1" if mutate_during_tests else "0",
                "CERT_MUTATION_MARKER": str(mutation_marker),
                "TRANSITVPN_CERTIFICATION_ACTIVE": "1",
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
        recorded = calls.read_text(encoding="utf-8").splitlines()
        temporary_root = Path(created_root.read_text(encoding="utf-8").strip())
        return completed, recorded, temporary_root

    def test_runner_has_an_executable_fail_fast_shell_contract(self) -> None:
        source = RUNNER.read_text(encoding="utf-8")

        self.assertEqual(source.splitlines()[0], "#!/usr/bin/env bash")
        self.assertEqual(stat.S_IMODE(RUNNER.stat().st_mode) & 0o111, 0o111)
        self.assertRegex(source, r"(?m)^set -euo pipefail$")
        self.assertRegex(source, r"(?m)^exec </dev/null$")
        self.assertRegex(source, r"(?m)^trap cleanup EXIT HUP INT TERM$")
        self.assertRegex(
            source,
            r'(?m)^\s*rm -rf -- "\$temporary_root" </dev/null$',
        )

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

    def test_public_active_flag_cannot_bypass_full_certification(self) -> None:
        completed, recorded, temporary_root = self.run_instrumented_runner()

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(temporary_root.exists(), "EXIT trap left its temporary tree behind")
        self.assertEqual([call.split("|ACTIVE=", 1)[0] for call in recorded], [
            f"CALL|-m|venv|{temporary_root / 'venv'}",
            "CALL|-m|pip|install|--disable-pip-version-check|--no-input|--quiet|"
            f"--requirement|{PROJECT_ROOT / 'requirements-certification.lock'}",
            "CALL|-m|pytest|--collect-only|-q|tests",
            "CALL|-m|pytest|-q|tests",
        ])
        self.assertTrue(all("|ACTIVE=1|" in call for call in recorded))
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "Collecting tests in clean environment...",
                "Running tests in clean environment...",
                "All acceptance checks passed.",
            ],
        )

    def test_committed_constraint_is_used_and_contains_only_exact_pins(self) -> None:
        completed, recorded, _ = self.run_instrumented_runner()
        lock_file = PROJECT_ROOT / "requirements-certification.lock"
        pins = [
            line.strip()
            for line in lock_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(pins, "certification lock must not be empty")
        for pin in pins:
            with self.subTest(pin=pin):
                self.assertRegex(pin, r"^[A-Za-z0-9_.-]+==[^=<>!~;,\s]+$")
        pip_call = next(call for call in recorded if "CALL|-m|pip|install|" in call)
        self.assertIn(f"|CONSTRAINT={lock_file}|", pip_call)

    def test_tracked_worktree_mutation_fails_but_unchanged_run_succeeds(self) -> None:
        unchanged, _, _ = self.run_instrumented_runner()
        mutated, _, _ = self.run_instrumented_runner(mutate_during_tests=True)

        self.assertEqual(unchanged.returncode, 0, unchanged.stderr)
        self.assertIn("All acceptance checks passed.", unchanged.stdout)
        self.assertNotEqual(mutated.returncode, 0)
        self.assertIn("pytest changed or staged tracked artifacts", mutated.stderr)
        self.assertNotIn("All acceptance checks passed.", mutated.stdout + mutated.stderr)

    def test_install_failure_is_credential_safe_and_never_claims_test_success(self) -> None:
        completed, recorded, _ = self.run_instrumented_runner(fail_install=True)
        diagnostics = completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(len(recorded), 2, recorded)
        self.assertIn("Certification dependency installation failed.", completed.stderr)
        self.assertNotIn("super-secret", diagnostics)
        self.assertNotIn("installation-secret", diagnostics)
        self.assertNotIn("Collecting tests", diagnostics)
        self.assertNotIn("Running tests", diagnostics)
        self.assertNotIn("All acceptance checks passed.", diagnostics)


if __name__ == "__main__":
    unittest.main()
