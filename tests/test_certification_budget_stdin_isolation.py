"""Black-box tests for certification command budget and stdin isolation."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT_ROOT / "scripts" / "certify-clean.sh"


class CertificationBudgetAndStdinTests(unittest.TestCase):
    def run_runner(
        self, *, mutate: bool = False, fail_collection: bool = False
    ) -> tuple[subprocess.CompletedProcess[str], list[str]]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fake_bin = root / "bin"
        fake_bin.mkdir()
        log = root / "commands.log"
        mutation = root / "mutation"

        python = fake_bin / "python3"
        python.write_text(
            textwrap.dedent(
                """\
                #!/bin/sh
                printf 'CMD python3' >> "$CERT_LOG"
                for argument in "$@"; do printf ' <%s>' "$argument" >> "$CERT_LOG"; done
                printf ' HASH=%s PLUGINS=%s NO_INPUT=%s PROMPT=%s CONSTRAINT=%s' \
                    "${PYTHONHASHSEED-}" "${PYTEST_DISABLE_PLUGIN_AUTOLOAD-}" \
                    "${PIP_NO_INPUT-}" "${GIT_TERMINAL_PROMPT-}" "${PIP_CONSTRAINT-}" >> "$CERT_LOG"
                if IFS= read -r stolen; then
                    printf ' STDIN=CONSUMED:<%s> ADDITIONAL_INPUT_PROMPT\\n' "$stolen" >> "$CERT_LOG"
                else
                    printf ' STDIN=EOF\\n' >> "$CERT_LOG"
                fi
                if [ "$1" = -m ] && [ "$2" = venv ]; then
                    /bin/mkdir -p "$3/bin"
                    /bin/cp "$0" "$3/bin/python"
                elif [ "$1" = -m ] && [ "$2" = pytest ] && \
                     [ "$3" = --collect-only ] && [ "${CERT_FAIL_COLLECTION-0}" = 1 ]; then
                    exit 7
                elif [ "$1" = -m ] && [ "$2" = pytest ] && \
                     [ "$3" != --collect-only ] && [ "${CERT_MUTATE-0}" = 1 ]; then
                    : > "$CERT_MUTATION"
                fi
                """
            ),
            encoding="utf-8",
        )
        python.chmod(0o755)

        git = fake_bin / "git"
        git.write_text(
            "#!/bin/sh\n"
            "printf 'CMD git' >> \"$CERT_LOG\"\n"
            "for argument in \"$@\"; do printf ' <%s>' \"$argument\" >> \"$CERT_LOG\"; done\n"
            "if IFS= read -r stolen; then printf ' STDIN=CONSUMED:<%s> ADDITIONAL_INPUT_PROMPT\\n' \"$stolen\" >> \"$CERT_LOG\"; "
            "else printf ' STDIN=EOF\\n' >> \"$CERT_LOG\"; fi\n"
            "if [ -e \"$CERT_MUTATION\" ]; then printf 'tracked mutation after tests\\n'; fi\n",
            encoding="utf-8",
        )
        git.chmod(0o755)

        mktemp = fake_bin / "mktemp"
        mktemp.write_text(
            "#!/bin/sh\n"
            "printf 'CMD mktemp <%s>' \"$1\" >> \"$CERT_LOG\"\n"
            "if IFS= read -r stolen; then printf ' STDIN=CONSUMED:<%s> ADDITIONAL_INPUT_PROMPT\\n' \"$stolen\" >> \"$CERT_LOG\"; "
            "else printf ' STDIN=EOF\\n' >> \"$CERT_LOG\"; fi\n"
            "created=\"$TMPDIR/certification-temporary-root\"\n"
            "/bin/mkdir \"$created\"\n"
            "printf '%s\\n' \"$created\"\n",
            encoding="utf-8",
        )
        mktemp.chmod(0o755)

        for command, real_command in (
            ("cmp", "/usr/bin/cmp"),
            ("pwd", "/bin/pwd"),
            ("rm", "/bin/rm"),
        ):
            wrapper = fake_bin / command
            wrapper.write_text(
                f"#!/bin/sh\nprintf 'CMD {command}' >> \"$CERT_LOG\"\n"
                "for argument in \"$@\"; do printf ' <%s>' \"$argument\" >> \"$CERT_LOG\"; done\n"
                "if IFS= read -r stolen; then printf ' STDIN=CONSUMED:<%s> ADDITIONAL_INPUT_PROMPT\\n' \"$stolen\" >> \"$CERT_LOG\"; "
                "else printf ' STDIN=EOF\\n' >> \"$CERT_LOG\"; fi\n"
                f"exec {real_command} \"$@\"\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o755)

        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{fake_bin}{os.pathsep}{env['PATH']}",
                "TMPDIR": str(root),
                "CERT_LOG": str(log),
                "CERT_MUTATE": "1" if mutate else "0",
                "CERT_FAIL_COLLECTION": "1" if fail_collection else "0",
                "CERT_MUTATION": str(mutation),
                "PYTHONHASHSEED": "hostile",
                "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "0",
                "PIP_NO_INPUT": "0",
                "GIT_TERMINAL_PROMPT": "1",
            }
        )
        completed = subprocess.run(
            [str(RUNNER)],
            cwd=PROJECT_ROOT,
            env=env,
            input="orchestrator-control-message-must-not-be-read\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        return completed, log.read_text(encoding="utf-8").splitlines()

    def test_success_is_bounded_noninteractive_locked_and_deterministic(self) -> None:
        completed, commands = self.run_runner()

        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertLessEqual(len(commands), 18, commands)
        self.assertTrue(commands, "the command counter observed no runner subprocesses")

        python_commands = [line for line in commands if line.startswith("CMD python3")]
        self.assertEqual(len(python_commands), 4, python_commands)
        self.assertTrue(all(line.endswith("STDIN=EOF") for line in python_commands), python_commands)
        self.assertTrue(all("NO_INPUT=1 PROMPT=0" in line for line in python_commands), python_commands)

        lock = PROJECT_ROOT / "requirements-certification.lock"
        pip = next(line for line in python_commands if " <-m> <pip> <install>" in line)
        self.assertIn(
            f" <-m> <pip> <install> <--disable-pip-version-check> <--no-input> <--quiet>"
            f" <--requirement> <{lock}>",
            pip,
        )
        self.assertNotIn(" <-e>", pip)

        collection = next(line for line in python_commands if " <pytest> <--collect-only>" in line)
        execution = next(
            line for line in python_commands if " <-m> <pytest> <-q> <tests>" in line
        )
        self.assertLess(commands.index(collection), commands.index(execution))
        self.assertIn(" HASH=0 PLUGINS=1", collection)
        self.assertEqual(collection.count("<--collect-only>"), 1)

    def test_supplied_stdin_cannot_be_consumed_or_trigger_an_input_prompt(self) -> None:
        completed, commands = self.run_runner()
        transcript = "\n".join(commands) + completed.stdout + completed.stderr

        self.assertEqual(completed.returncode, 0, transcript)
        self.assertTrue(all(command.endswith("STDIN=EOF") for command in commands), commands)
        self.assertNotIn("orchestrator-control-message-must-not-be-read", transcript)
        self.assertNotIn("STDIN=CONSUMED", transcript)
        self.assertNotIn("ADDITIONAL_INPUT_PROMPT", transcript)

    def test_tracked_state_integrity_check_still_rejects_test_mutation(self) -> None:
        completed, commands = self.run_runner(mutate=True)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("pytest changed or staged tracked artifacts", completed.stderr)
        self.assertNotIn("All acceptance checks passed.", completed.stdout + completed.stderr)
        self.assertEqual(sum(line.startswith("CMD git") for line in commands), 6, commands)
        self.assertEqual(sum(line.startswith("CMD cmp") for line in commands), 1, commands)

    def test_collection_failure_is_bounded_detached_and_never_runs_tests(self) -> None:
        completed, commands = self.run_runner(fail_collection=True)
        transcript = "\n".join(commands) + completed.stdout + completed.stderr

        self.assertNotEqual(completed.returncode, 0)
        self.assertLessEqual(len(commands), 18, commands)
        self.assertTrue(all(command.endswith("STDIN=EOF") for command in commands), commands)
        self.assertEqual(
            sum(" <-m> <pytest> <--collect-only> <-q> <tests>" in line for line in commands),
            1,
            commands,
        )
        self.assertFalse(
            any(" <-m> <pytest> <-q> <tests>" in line for line in commands), commands
        )
        self.assertNotIn("STDIN=CONSUMED", transcript)
        self.assertNotIn("ADDITIONAL_INPUT_PROMPT", transcript)
        self.assertNotIn("Running tests in clean environment", transcript)
        self.assertIn("pytest did not complete successfully", completed.stderr)
        self.assertNotIn("All acceptance checks passed.", transcript)


if __name__ == "__main__":
    unittest.main()
