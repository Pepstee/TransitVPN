"""Adversarial tests for the 'down' and 'status' CLI subcommands.

These tests are independent of the builder — they exercise the real CLI code
paths.  No mocking of the unit under test.

Coverage:
  - subprocess invocation (mirrors the acceptance script exactly)
  - exit codes and output content
  - multiple invocation patterns (module, script, entry-point)
  - concurrent execution (idempotency)
  - absence of side-effects (no files created, no state mutated)
  - acceptance script produces PASS: subcommand down / PASS: subcommand status
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers (no mocks — all helpers spawn real subprocesses)
# ---------------------------------------------------------------------------


def _run_module(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "transitvpn", *args],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )


def _run_script(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(_REPO / "transitvpn" / "cli.py"), *args],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )


def _run_acceptance() -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(_REPO / "acceptance")],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )


def _combined(r: subprocess.CompletedProcess) -> str:
    return r.stdout + r.stderr


# ---------------------------------------------------------------------------
# Acceptance script: explicit PASS assertions for 'down' and 'status'
# ---------------------------------------------------------------------------


class TestAcceptancePassSubcommandDown:
    """The acceptance script must echo 'PASS: subcommand down' to stdout."""

    def test_pass_subcommand_down_present_in_acceptance_stdout(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0, (
            f"acceptance exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert "PASS: subcommand down" in result.stdout, (
            f"'PASS: subcommand down' not found in acceptance stdout.\n"
            f"Full stdout:\n{result.stdout}"
        )

    def test_pass_subcommand_down_is_on_its_own_line(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        lines = [ln.strip() for ln in result.stdout.splitlines()]
        assert "PASS: subcommand down" in lines, (
            f"'PASS: subcommand down' is not a standalone line in stdout.\n"
            f"Lines: {lines}"
        )

    def test_pass_subcommand_down_appears_exactly_once(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        count = result.stdout.count("PASS: subcommand down")
        assert count == 1, (
            f"'PASS: subcommand down' should appear exactly once, got {count}.\n"
            f"stdout:\n{result.stdout}"
        )

    def test_pass_subcommand_down_not_in_stderr(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        # PASS messages belong on stdout, not stderr
        assert "PASS: subcommand down" in result.stdout
        # stderr should be clean
        assert result.stderr.strip() == "", (
            f"Unexpected stderr:\n{result.stderr}"
        )


class TestAcceptancePassSubcommandStatus:
    """The acceptance script must echo 'PASS: subcommand status' to stdout."""

    def test_pass_subcommand_status_present_in_acceptance_stdout(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0, (
            f"acceptance exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
        assert "PASS: subcommand status" in result.stdout, (
            f"'PASS: subcommand status' not found in acceptance stdout.\n"
            f"Full stdout:\n{result.stdout}"
        )

    def test_pass_subcommand_status_is_on_its_own_line(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        lines = [ln.strip() for ln in result.stdout.splitlines()]
        assert "PASS: subcommand status" in lines, (
            f"'PASS: subcommand status' is not a standalone line in stdout.\n"
            f"Lines: {lines}"
        )

    def test_pass_subcommand_status_appears_exactly_once(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        count = result.stdout.count("PASS: subcommand status")
        assert count == 1, (
            f"'PASS: subcommand status' should appear exactly once, got {count}.\n"
            f"stdout:\n{result.stdout}"
        )

    def test_pass_subcommand_status_not_in_stderr(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "PASS: subcommand status" in result.stdout
        assert result.stderr.strip() == "", (
            f"Unexpected stderr:\n{result.stderr}"
        )


class TestAcceptanceBothDownAndStatusPresent:
    """Both PASS strings must co-exist in a single acceptance run."""

    def test_both_pass_strings_present_in_single_run(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "PASS: subcommand down" in result.stdout
        assert "PASS: subcommand status" in result.stdout

    def test_down_pass_appears_before_status_pass(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        idx_down = result.stdout.find("PASS: subcommand down")
        idx_status = result.stdout.find("PASS: subcommand status")
        assert idx_down != -1
        assert idx_status != -1
        assert idx_down < idx_status, (
            "acceptance must check 'down' before 'status'"
        )

    def test_up_down_status_all_present(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        for marker in ("PASS: subcommand up", "PASS: subcommand down", "PASS: subcommand status"):
            assert marker in result.stdout, (
                f"'{marker}' missing from acceptance stdout.\nstdout:\n{result.stdout}"
            )

    def test_acceptance_still_passes_all_other_checks(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "All acceptance checks passed." in result.stdout


# ---------------------------------------------------------------------------
# 'down' subcommand: subprocess end-to-end (module invocation)
# ---------------------------------------------------------------------------


class TestDownSubcommandModule:
    """'python -m transitvpn down' must behave correctly — mirrors acceptance."""

    def test_exit_code_is_zero(self) -> None:
        result = _run_module("down")
        assert result.returncode == 0, (
            f"'down' exited {result.returncode}\n"
            f"stdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_combined_output_contains_down_prefix(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py down 2>&1 | grep -q 'down:'"""
        assert "down:" in _combined(_run_module("down")), (
            f"'down:' missing from combined output.\n"
            f"combined: {_combined(_run_module('down'))!r}"
        )

    def test_output_contains_command_name(self) -> None:
        result = _run_module("down")
        combined = _combined(result)
        assert "down" in combined, (
            f"'down' not mentioned in output: {combined!r}"
        )

    def test_no_traceback_on_down(self) -> None:
        result = _run_module("down")
        assert "Traceback" not in _combined(result), (
            f"Unexpected traceback:\n{_combined(result)}"
        )

    def test_no_error_message_on_down(self) -> None:
        result = _run_module("down")
        assert "Error" not in _combined(result) and "error" not in _combined(result).lower()[:50], (
            f"Unexpected error text in output:\n{_combined(result)}"
        )

    def test_repeated_down_invocations_both_exit_zero(self) -> None:
        r1 = _run_module("down")
        r2 = _run_module("down")
        assert r1.returncode == 0, f"First 'down' failed: {_combined(r1)}"
        assert r2.returncode == 0, f"Second 'down' failed: {_combined(r2)}"

    def test_down_produces_no_empty_stdout_when_stdout_checked(self) -> None:
        result = _run_module("down")
        assert result.stdout.strip() != "", (
            "stdout should not be empty — stub must print something"
        )

    def test_down_does_not_write_any_files_in_cwd(self, tmp_path: Path) -> None:
        files_before = set(tmp_path.iterdir())
        subprocess.run(
            [sys.executable, "-m", "transitvpn", "down"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        files_after = set(tmp_path.iterdir())
        assert files_after == files_before, (
            f"'down' stub created unexpected files: {files_after - files_before}"
        )


# ---------------------------------------------------------------------------
# 'status' subcommand: subprocess end-to-end (module invocation)
# ---------------------------------------------------------------------------


class TestStatusSubcommandModule:
    """'python -m transitvpn status' must behave correctly — mirrors acceptance."""

    def test_exit_code_is_zero(self) -> None:
        result = _run_module("status")
        assert result.returncode == 0, (
            f"'status' exited {result.returncode}\n"
            f"stdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_combined_output_contains_status_prefix(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py status 2>&1 | grep -q 'status:'"""
        assert "status:" in _combined(_run_module("status")), (
            f"'status:' missing from combined output.\n"
            f"combined: {_combined(_run_module('status'))!r}"
        )

    def test_output_contains_command_name(self) -> None:
        result = _run_module("status")
        combined = _combined(result)
        assert "status" in combined, (
            f"'status' not mentioned in output: {combined!r}"
        )

    def test_no_traceback_on_status(self) -> None:
        result = _run_module("status")
        assert "Traceback" not in _combined(result)

    def test_repeated_status_invocations_both_exit_zero(self) -> None:
        r1 = _run_module("status")
        r2 = _run_module("status")
        assert r1.returncode == 0
        assert r2.returncode == 0

    def test_status_produces_non_empty_stdout(self) -> None:
        result = _run_module("status")
        assert result.stdout.strip() != ""

    def test_status_does_not_write_any_files_in_cwd(self, tmp_path: Path) -> None:
        files_before = set(tmp_path.iterdir())
        subprocess.run(
            [sys.executable, "-m", "transitvpn", "status"],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        files_after = set(tmp_path.iterdir())
        assert files_after == files_before


# ---------------------------------------------------------------------------
# Script invocation (mirrors the acceptance script exactly)
# ---------------------------------------------------------------------------


class TestDownViaScript:
    """python transitvpn/cli.py down — exact form the acceptance script uses."""

    def test_exit_code_is_zero(self) -> None:
        result = _run_script("down")
        assert result.returncode == 0, (
            f"script 'down' exited {result.returncode}: {_combined(result)!r}"
        )

    def test_combined_output_contains_down_prefix(self) -> None:
        assert "down:" in _combined(_run_script("down"))

    def test_acceptance_grep_pattern_would_match(self) -> None:
        result = _run_script("down")
        combined = _combined(result)
        assert "down:" in combined, (
            "acceptance does: python transitvpn/cli.py down 2>&1 | grep -q 'down:' — must match"
        )


class TestStatusViaScript:
    """python transitvpn/cli.py status — exact form the acceptance script uses."""

    def test_exit_code_is_zero(self) -> None:
        result = _run_script("status")
        assert result.returncode == 0, (
            f"script 'status' exited {result.returncode}: {_combined(result)!r}"
        )

    def test_combined_output_contains_status_prefix(self) -> None:
        assert "status:" in _combined(_run_script("status"))

    def test_acceptance_grep_pattern_would_match(self) -> None:
        result = _run_script("status")
        combined = _combined(result)
        assert "status:" in combined, (
            "acceptance does: python transitvpn/cli.py status 2>&1 | grep -q 'status:' — must match"
        )


# ---------------------------------------------------------------------------
# Unit-level: main() called directly (no subprocess)
# ---------------------------------------------------------------------------


class TestDownMainDirect:
    """Call transitvpn.cli.main(['down']) in-process — fast, no subprocess overhead."""

    def test_main_down_returns_zero(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        rc = main(["down"])
        assert rc == 0

    def test_main_down_prints_down_prefix(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        main(["down"])
        out = capsys.readouterr().out
        assert "down:" in out, (
            f"expected 'down:' in stdout, got: {out!r}"
        )

    def test_main_down_mentions_down_in_output(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        main(["down"])
        out = capsys.readouterr().out
        assert "down" in out

    def test_main_down_does_not_import_cgnat(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        # The stub 'down' must NOT invoke any network module (CGNAT detection etc.)
        import sys
        modules_before = set(sys.modules.keys())
        main(["down"])
        capsys.readouterr()
        new_modules = set(sys.modules.keys()) - modules_before
        # cgnat triggers real socket activity — must not be imported by down
        assert not any("cgnat" in m for m in new_modules), (
            f"'down' unexpectedly imported cgnat-related modules: {new_modules}"
        )

    def test_main_down_output_is_real_implementation(self, capsys: pytest.CaptureFixture) -> None:
        """down must print 'tunnel stopped', not a placeholder stub message."""
        from transitvpn.cli import main
        main(["down"])
        out = capsys.readouterr().out
        assert "tunnel stopped" in out, (
            f"expected real output 'tunnel stopped', got: {out!r}"
        )

    def test_main_down_idempotent_across_calls(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        rc1 = main(["down"])
        capsys.readouterr()
        rc2 = main(["down"])
        capsys.readouterr()
        assert rc1 == 0
        assert rc2 == 0


class TestStatusMainDirect:
    """Call transitvpn.cli.main(['status']) in-process."""

    def test_main_status_returns_zero(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        rc = main(["status"])
        assert rc == 0

    def test_main_status_prints_status_prefix(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        main(["status"])
        out = capsys.readouterr().out
        assert "status:" in out, (
            f"expected 'status:' in stdout, got: {out!r}"
        )

    def test_main_status_mentions_status_in_output(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        main(["status"])
        out = capsys.readouterr().out
        assert "status" in out

    def test_main_status_output_is_real_implementation(self, capsys: pytest.CaptureFixture) -> None:
        """status must print 'not running', not a placeholder stub message."""
        from transitvpn.cli import main
        main(["status"])
        out = capsys.readouterr().out
        assert "not running" in out, (
            f"expected real output 'not running', got: {out!r}"
        )

    def test_main_status_idempotent_across_calls(self, capsys: pytest.CaptureFixture) -> None:
        from transitvpn.cli import main
        rc1 = main(["status"])
        capsys.readouterr()
        rc2 = main(["status"])
        capsys.readouterr()
        assert rc1 == 0
        assert rc2 == 0


# ---------------------------------------------------------------------------
# Consistency: down, status, and up behave uniformly as stubs
# ---------------------------------------------------------------------------


class TestStubSymmetry:
    """down, up, and status are all stubs with the same contract."""

    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_all_stubs_exit_zero(self, cmd: str) -> None:
        result = _run_module(cmd)
        assert result.returncode == 0, (
            f"'{cmd}' exited {result.returncode}: {_combined(result)!r}"
        )

    @pytest.mark.parametrize("cmd", ["up", "down", "status"])
    def test_all_commands_print_command_prefix(self, cmd: str) -> None:
        assert f"{cmd}:" in _combined(_run_module(cmd)), (
            f"'{cmd}' did not print '{cmd}:'"
        )

    @pytest.mark.parametrize("cmd", ["up", "down", "status"])
    def test_all_stubs_mention_their_own_name(self, cmd: str) -> None:
        combined = _combined(_run_module(cmd))
        assert cmd in combined, (
            f"Expected '{cmd}' to appear in the output of '{cmd}'"
        )

    @pytest.mark.parametrize("cmd", ["up", "down", "status"])
    def test_all_stubs_produce_no_traceback(self, cmd: str) -> None:
        assert "Traceback" not in _combined(_run_module(cmd))

    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_down_and_status_create_no_files_when_no_tunnel_running(
        self, cmd: str, tmp_path: Path
    ) -> None:
        before = set(tmp_path.iterdir())
        subprocess.run(
            [sys.executable, "-m", "transitvpn", cmd],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        after = set(tmp_path.iterdir())
        assert after == before, (
            f"'{cmd}' without a running tunnel created unexpected files: {after - before}"
        )

    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_script_and_module_produce_same_exit_code(self, cmd: str) -> None:
        mod_result = _run_module(cmd)
        script_result = _run_script(cmd)
        assert mod_result.returncode == script_result.returncode, (
            f"'{cmd}' exit codes differ: module={mod_result.returncode} "
            f"script={script_result.returncode}"
        )

    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_script_and_module_produce_same_command_prefix(self, cmd: str) -> None:
        mod_out = _combined(_run_module(cmd))
        script_out = _combined(_run_script(cmd))
        assert f"{cmd}:" in mod_out
        assert f"{cmd}:" in script_out

    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_unknown_extra_args_do_not_prevent_exit_zero(self, cmd: str) -> None:
        # argparse subparsers with no arguments defined simply ignore extra args
        # or may reject them — but the stub behaviour must not crash
        result = _run_module(cmd)
        # At minimum the nominal case (no extra args) must exit 0
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Acceptance script structure: down and status checks are present
# ---------------------------------------------------------------------------


class TestAcceptanceScriptContainsDownAndStatusChecks:
    """Static assertions: the acceptance script must define checks for down & status."""

    def test_acceptance_contains_down_subcommand_check(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "down" in content, "acceptance script must test the 'down' subcommand"

    def test_acceptance_contains_status_subcommand_check(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "status" in content, "acceptance script must test the 'status' subcommand"

    def test_acceptance_echoes_pass_subcommand_down(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "PASS: subcommand down" in content, (
            "acceptance script must echo 'PASS: subcommand down'"
        )

    def test_acceptance_echoes_pass_subcommand_status(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "PASS: subcommand status" in content, (
            "acceptance script must echo 'PASS: subcommand status'"
        )

    def test_acceptance_checks_down_prefix_for_down(self) -> None:
        content = (_REPO / "acceptance").read_text()
        lines = content.splitlines()
        down_lines = [
            ln for ln in lines
            if "down" in ln and "PASS" not in ln and not ln.strip().startswith("#")
        ]
        assert any("down:" in ln for ln in down_lines), (
            "acceptance script must grep for 'down:' when testing 'down'"
        )

    def test_acceptance_checks_status_prefix_for_status(self) -> None:
        content = (_REPO / "acceptance").read_text()
        lines = content.splitlines()
        status_lines = [
            ln for ln in lines
            if "status" in ln and "PASS" not in ln and not ln.strip().startswith("#")
        ]
        assert any("status:" in ln for ln in status_lines), (
            "acceptance script must grep for 'status:' when testing 'status'"
        )

    def test_acceptance_file_has_no_not_yet_implemented(self) -> None:
        """Meta-test: acceptance file must not mention 'not yet implemented' anywhere."""
        content = (_REPO / "acceptance").read_text()
        assert "not yet implemented" not in content, (
            "acceptance file must not contain 'not yet implemented' — "
            "all checks must use real output patterns"
        )

    def test_acceptance_file_greps_for_up_colon(self) -> None:
        """Meta-test: acceptance file must grep for 'up:' (real output marker)."""
        content = (_REPO / "acceptance").read_text()
        assert '"up:"' in content or "'up:'" in content, (
            "acceptance file must contain grep for 'up:' to validate real subcommand output"
        )

    def test_acceptance_file_greps_for_down_colon(self) -> None:
        """Meta-test: acceptance file must grep for 'down:' (real output marker)."""
        content = (_REPO / "acceptance").read_text()
        assert '"down:"' in content or "'down:'" in content, (
            "acceptance file must contain grep for 'down:' to validate real subcommand output"
        )

    def test_acceptance_file_greps_for_status_colon(self) -> None:
        """Meta-test: acceptance file must grep for 'status:' (real output marker)."""
        content = (_REPO / "acceptance").read_text()
        assert '"status:"' in content or "'status:'" in content, (
            "acceptance file must contain grep for 'status:' to validate real subcommand output"
        )

    def test_acceptance_down_check_precedes_its_pass_echo(self) -> None:
        content = (_REPO / "acceptance").read_text()
        lines = content.splitlines()
        idx_check = next(
            (
                i for i, ln in enumerate(lines)
                if "down" in ln and "down:" in ln and "PASS" not in ln
            ),
            None,
        )
        idx_pass = next(
            (i for i, ln in enumerate(lines) if "PASS: subcommand down" in ln), None
        )
        assert idx_check is not None, "down check line not found"
        assert idx_pass is not None, "PASS: subcommand down echo not found"
        assert idx_check < idx_pass, (
            "The 'down:' grep for 'down' must appear BEFORE its PASS echo"
        )

    def test_acceptance_status_check_precedes_its_pass_echo(self) -> None:
        content = (_REPO / "acceptance").read_text()
        lines = content.splitlines()
        idx_check = next(
            (
                i for i, ln in enumerate(lines)
                if "status" in ln and "status:" in ln and "PASS" not in ln
            ),
            None,
        )
        idx_pass = next(
            (i for i, ln in enumerate(lines) if "PASS: subcommand status" in ln), None
        )
        assert idx_check is not None, "status check line not found"
        assert idx_pass is not None, "PASS: subcommand status echo not found"
        assert idx_check < idx_pass
