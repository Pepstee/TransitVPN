"""End-to-end acceptance and subprocess tests for the transitvpn CLI.

Covers the acceptance criteria:
  - bash acceptance exits 0
  - grep -c 'PASS:' acceptance | awk '{exit ($1 < 4)}' (>=4 PASS: in file)

Also verifies that bootstrap --dry-run and keygen subprocess paths exit 0 and
produce the expected output, mirroring exactly what the acceptance shell script
checks.  No mocking — every test exercises real code paths.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

# Repository root — directory containing the acceptance script and transitvpn/
_REPO = Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run the transitvpn CLI via 'python -m transitvpn' with the test interpreter."""
    return subprocess.run(
        [sys.executable, "-m", "transitvpn", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or _REPO),
    )


def _run_script(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run transitvpn/cli.py as a script — exactly as the acceptance script does."""
    return subprocess.run(
        [sys.executable, str(_REPO / "transitvpn" / "cli.py"), *args],
        capture_output=True,
        text=True,
        cwd=str(cwd or _REPO),
    )


def _combined(result: subprocess.CompletedProcess) -> str:
    return result.stdout + result.stderr


# ---------------------------------------------------------------------------
# Acceptance file integrity (mirrors: grep -c 'PASS:' acceptance | awk ...)
# ---------------------------------------------------------------------------


class TestAcceptanceFileIntegrity:
    def test_acceptance_file_exists(self) -> None:
        assert (_REPO / "acceptance").exists(), "acceptance script missing"

    def test_acceptance_file_is_executable(self) -> None:
        assert os.access(_REPO / "acceptance", os.X_OK), (
            "acceptance script must be executable"
        )

    def test_acceptance_file_has_bash_shebang(self) -> None:
        first = (_REPO / "acceptance").read_text().splitlines()[0]
        assert first.startswith("#!") and "bash" in first, (
            f"Expected bash shebang, got: {first!r}"
        )

    def test_acceptance_file_has_at_least_four_pass_strings(self) -> None:
        """Mirrors: grep -c 'PASS:' acceptance | awk '{exit ($1 < 4)}'"""
        count = (_REPO / "acceptance").read_text().count("PASS:")
        assert count >= 4, f"Expected >=4 'PASS:' strings in acceptance file, got {count}"

    def test_acceptance_file_contains_bootstrap_dry_run_check(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "bootstrap" in content and "--dry-run" in content

    def test_acceptance_file_contains_keygen_check(self) -> None:
        assert "keygen" in (_REPO / "acceptance").read_text()

    def test_acceptance_file_checks_cgnat_output(self) -> None:
        assert "cgnat:" in (_REPO / "acceptance").read_text()

    def test_acceptance_file_checks_vless_uuid_output(self) -> None:
        assert "vless_uuid" in (_REPO / "acceptance").read_text()

    def test_acceptance_file_has_no_not_yet_implemented(self) -> None:
        """The acceptance file must not contain any 'not yet implemented' stubs."""
        content = (_REPO / "acceptance").read_text()
        assert "not yet implemented" not in content, (
            "acceptance file must not contain 'not yet implemented'"
            " — all checks must use real output"
        )

    def test_acceptance_file_greps_for_up_colon(self) -> None:
        """acceptance must verify 'up:' in CLI output — real implementation marker."""
        content = (_REPO / "acceptance").read_text()
        assert '"up:"' in content or "'up:'" in content, (
            "acceptance file must grep for 'up:' to validate real subcommand output"
        )

    def test_acceptance_file_greps_for_down_colon(self) -> None:
        """acceptance must verify 'down:' in CLI output — real implementation marker."""
        content = (_REPO / "acceptance").read_text()
        assert '"down:"' in content or "'down:'" in content, (
            "acceptance file must grep for 'down:' to validate real subcommand output"
        )

    def test_acceptance_file_greps_for_status_colon(self) -> None:
        """acceptance must verify 'status:' in CLI output — real implementation marker."""
        content = (_REPO / "acceptance").read_text()
        assert '"status:"' in content or "'status:'" in content, (
            "acceptance file must grep for 'status:' to validate real subcommand output"
        )


# ---------------------------------------------------------------------------
# bootstrap --dry-run: subprocess end-to-end (no mocks)
# ---------------------------------------------------------------------------


class TestBootstrapDryRunSubprocess:
    """Run 'bootstrap --dry-run' as a real subprocess — no detect_cgnat mocking."""

    def test_exit_code_is_zero(self) -> None:
        result = _run("bootstrap", "--dry-run")
        assert result.returncode == 0, (
            f"exit {result.returncode}\nstdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_combined_output_contains_cgnat_label(self) -> None:
        """Mirrors: python transitvpn/cli.py bootstrap --dry-run 2>&1 | grep -q 'cgnat:'"""
        assert "cgnat:" in _combined(_run("bootstrap", "--dry-run"))

    def test_stdout_contains_cgnat_label(self) -> None:
        # cgnat: must appear in stdout (not just stderr)
        assert "cgnat:" in _run("bootstrap", "--dry-run").stdout

    def test_stdout_contains_cgnat_unknown_because_dry_run(self) -> None:
        assert "cgnat: unknown" in _run("bootstrap", "--dry-run").stdout

    def test_stdout_contains_vless_uri_label(self) -> None:
        assert "vless_uri:" in _run("bootstrap", "--dry-run").stdout

    def test_stdout_contains_vless_scheme(self) -> None:
        assert "vless://" in _run("bootstrap", "--dry-run").stdout

    def test_stdout_contains_ss_uri_label(self) -> None:
        assert "ss_uri:" in _run("bootstrap", "--dry-run").stdout

    def test_stdout_contains_ss_scheme(self) -> None:
        assert "ss://" in _run("bootstrap", "--dry-run").stdout

    def test_dry_run_does_not_create_state_directory(self, tmp_path: Path) -> None:
        result = _run("bootstrap", "--dry-run", cwd=tmp_path)
        assert result.returncode == 0
        assert not (tmp_path / "state").exists(), (
            "--dry-run must not create state/"
        )

    def test_dry_run_does_not_create_xray_config(self, tmp_path: Path) -> None:
        _run("bootstrap", "--dry-run", cwd=tmp_path)
        assert not (tmp_path / "state" / "xray-server.json").exists()

    def test_dry_run_does_not_create_ss_config(self, tmp_path: Path) -> None:
        _run("bootstrap", "--dry-run", cwd=tmp_path)
        assert not (tmp_path / "state" / "ss-server.json").exists()

    def test_dry_run_output_does_not_contain_wrote_message(self) -> None:
        assert "wrote" not in _run("bootstrap", "--dry-run").stdout

    def test_vless_uri_uses_fallback_host_when_no_public_ip(self) -> None:
        # dry-run skips network probes → public_ip is None → host falls back to 0.0.0.0
        out = _run("bootstrap", "--dry-run").stdout
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert "0.0.0.0" in vless_line

    def test_vless_uri_uses_port_443(self) -> None:
        out = _run("bootstrap", "--dry-run").stdout
        vless_line = next(ln for ln in out.splitlines() if "vless_uri:" in ln)
        assert ":443" in vless_line

    def test_ss_uri_uses_port_8388(self) -> None:
        out = _run("bootstrap", "--dry-run").stdout
        ss_line = next(ln for ln in out.splitlines() if "ss_uri:" in ln and "vless" not in ln)
        assert ":8388" in ss_line

    def test_via_script_exit_code_is_zero(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py bootstrap --dry-run"""
        result = _run_script("bootstrap", "--dry-run")
        assert result.returncode == 0, (
            f"exit {result.returncode}\nstdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_via_script_combined_output_contains_cgnat(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py bootstrap
        --dry-run 2>&1 | grep -q 'cgnat:'"""
        assert "cgnat:" in _combined(_run_script("bootstrap", "--dry-run"))

    def test_repeated_dry_runs_both_exit_zero(self) -> None:
        r1 = _run("bootstrap", "--dry-run")
        r2 = _run("bootstrap", "--dry-run")
        assert r1.returncode == 0
        assert r2.returncode == 0

    def test_stdout_contains_dry_run_detail_about_skipped_probes(self) -> None:
        # detect_cgnat(dry_run=True) always adds a "dry-run" detail
        out = _run("bootstrap", "--dry-run").stdout
        assert "dry-run" in out or "skipped" in out


# ---------------------------------------------------------------------------
# keygen: subprocess end-to-end (no mocks)
# ---------------------------------------------------------------------------


class TestKeygenSubprocess:
    """Run 'keygen' as a real subprocess — no mocking."""

    def test_exit_code_is_zero(self) -> None:
        result = _run("keygen")
        assert result.returncode == 0, (
            f"exit {result.returncode}\nstdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_combined_output_contains_vless_uuid_label(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py keygen 2>&1 | grep -q 'vless_uuid'"""
        assert "vless_uuid" in _combined(_run("keygen"))

    def test_stdout_contains_vless_uuid_label(self) -> None:
        assert "vless_uuid" in _run("keygen").stdout

    def test_stdout_contains_reality_private_key_label(self) -> None:
        assert "reality_private_key" in _run("keygen").stdout

    def test_stdout_contains_reality_public_key_label(self) -> None:
        assert "reality_public_key" in _run("keygen").stdout

    def test_stdout_contains_ss_password_label(self) -> None:
        assert "ss_password" in _run("keygen").stdout

    def test_stdout_has_at_least_four_non_empty_lines(self) -> None:
        out = _run("keygen").stdout
        lines = [ln for ln in out.splitlines() if ln.strip()]
        assert len(lines) >= 4, f"Expected >=4 output lines, got {len(lines)}: {out!r}"

    def test_uuid_value_is_uuid_v4_format(self) -> None:
        out = _run("keygen").stdout
        uuid_line = next((ln for ln in out.splitlines() if "vless_uuid" in ln), None)
        assert uuid_line is not None, f"vless_uuid line not found in: {out!r}"
        value = uuid_line.split(":", 1)[1].strip()
        assert re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            value,
        ), f"vless_uuid value is not UUID v4: {value!r}"

    def test_private_key_and_public_key_values_differ(self) -> None:
        out = _run("keygen").stdout
        lines = {ln.split(":")[0].strip(): ln.split(":", 1)[1].strip()
                 for ln in out.splitlines() if ":" in ln}
        priv = lines.get("reality_private_key")
        pub = lines.get("reality_public_key")
        assert priv is not None and pub is not None
        assert priv != pub

    def test_successive_calls_produce_different_uuids(self) -> None:
        def _uuid(out: str) -> str:
            for line in out.splitlines():
                if "vless_uuid" in line:
                    return line.split(":", 1)[1].strip()
            raise AssertionError(f"vless_uuid not in: {out!r}")

        r1, r2 = _run("keygen"), _run("keygen")
        assert r1.returncode == 0 and r2.returncode == 0
        assert _uuid(r1.stdout) != _uuid(r2.stdout), (
            "Consecutive keygen calls must produce distinct UUIDs"
        )

    def test_successive_calls_produce_different_private_keys(self) -> None:
        def _priv(out: str) -> str:
            for line in out.splitlines():
                if "reality_private_key" in line:
                    return line.split(":", 1)[1].strip()
            raise AssertionError(f"reality_private_key not in: {out!r}")

        r1, r2 = _run("keygen"), _run("keygen")
        assert _priv(r1.stdout) != _priv(r2.stdout)

    def test_private_key_value_is_urlsafe_base64(self) -> None:
        out = _run("keygen").stdout
        priv_line = next((ln for ln in out.splitlines() if "reality_private_key" in ln), None)
        assert priv_line is not None
        value = priv_line.split(":", 1)[1].strip()
        assert "+" not in value and "/" not in value, (
            f"reality_private_key must be URL-safe base64: {value!r}"
        )

    def test_via_script_exit_code_is_zero(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py keygen"""
        result = _run_script("keygen")
        assert result.returncode == 0, (
            f"exit {result.returncode}\nstdout:{result.stdout!r}\nstderr:{result.stderr!r}"
        )

    def test_via_script_combined_output_contains_vless_uuid(self) -> None:
        """Mirrors acceptance: python transitvpn/cli.py keygen 2>&1 | grep -q 'vless_uuid'"""
        assert "vless_uuid" in _combined(_run_script("keygen"))


# ---------------------------------------------------------------------------
# --help and --version subprocess checks
# ---------------------------------------------------------------------------


class TestHelpVersionSubprocess:
    def test_help_exits_zero(self) -> None:
        assert _run("--help").returncode == 0

    def test_help_produces_non_empty_output(self) -> None:
        result = _run("--help")
        assert _combined(result).strip() != ""

    def test_version_exits_zero(self) -> None:
        # argparse sends --version output to stdout on Python 3.10+ (was stderr before)
        result = _run("--version")
        assert result.returncode == 0

    def test_version_output_contains_version_number(self) -> None:
        result = _run("--version")
        assert "0.1.0" in _combined(result)

    def test_via_script_help_exits_zero(self) -> None:
        assert _run_script("--help").returncode == 0

    def test_via_script_version_exits_zero(self) -> None:
        assert _run_script("--version").returncode == 0


# ---------------------------------------------------------------------------
# 'up', 'down', 'status' stub subcommands
# ---------------------------------------------------------------------------


class TestStubSubcommandsSubprocess:
    @pytest.mark.parametrize("cmd", ["down", "status"])
    def test_stub_command_exits_zero(self, cmd: str) -> None:
        result = _run(cmd)
        assert result.returncode == 0, (
            f"'{cmd}' exited {result.returncode}: {_combined(result)!r}"
        )

    @pytest.mark.parametrize("cmd", ["up", "down", "status"])
    def test_stub_command_output_contains_command_prefix(self, cmd: str) -> None:
        """Mirrors acceptance: transitvpn <cmd> 2>&1 | grep -q '<cmd>:'"""
        assert f"{cmd}:" in _combined(_run(cmd))

    def test_up_output_is_real_implementation(self) -> None:
        """'up' without config must report an error, never a fake success."""
        out = _combined(_run("up"))
        assert "up: error:" in out, (
            f"expected 'up: error:' in up output (no config present), got: {out!r}"
        )

    def test_down_output_is_real_implementation(self) -> None:
        """'down' must print its real implementation message."""
        out = _combined(_run("down"))
        assert "tunnel stopped" in out, (
            f"expected 'tunnel stopped' in down output, got: {out!r}"
        )

    def test_status_output_is_real_implementation(self) -> None:
        """'status' must print its real implementation message."""
        out = _combined(_run("status"))
        assert "not running" in out, (
            f"expected 'not running' in status output, got: {out!r}"
        )

    def test_via_script_up_output_contains_up_prefix(self) -> None:
        assert "up:" in _combined(_run_script("up"))

    def test_via_script_up_exits_nonzero_without_config(self) -> None:
        assert _run_script("up").returncode == 1


# ---------------------------------------------------------------------------
# py_compile check on the main modules (mirrors acceptance step 1)
# ---------------------------------------------------------------------------


class TestPyCompileSubprocess:
    @pytest.mark.parametrize("module_path", [
        "transitvpn/__init__.py",
        "transitvpn/cli.py",
        "transitvpn/keygen.py",
        "transitvpn/cgnat.py",
        "transitvpn/config.py",
        "transitvpn/server.py",
        "transitvpn/qrcode.py",
    ])
    def test_module_compiles_without_syntax_errors(self, module_path: str) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "py_compile", module_path],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, (
            f"py_compile failed for {module_path}: {result.stderr!r}"
        )


# ---------------------------------------------------------------------------
# Import check (mirrors acceptance step 2)
# ---------------------------------------------------------------------------


class TestImportsSubprocess:
    def test_all_acceptance_imports_succeed(self) -> None:
        script = (
            "from transitvpn.cgnat import CgnatStatus, CgnatResult, detect_cgnat; "
            "from transitvpn.keygen import Keys, generate_keys; "
            "from transitvpn.config import VlessConfig, ShadowsocksConfig, RelayConfig; "
            "from transitvpn.server import build_xray_config, build_ss_config; "
            "from transitvpn.cli import build_parser, main"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, (
            f"Import check failed:\n{result.stderr}"
        )

    def test_transitvpn_package_importable(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "import transitvpn"],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, result.stderr

    def test_cli_module_importable(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "from transitvpn.cli import build_parser, main"],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, result.stderr

    def test_keygen_module_importable(self) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "from transitvpn.keygen import Keys, generate_keys"],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# Full acceptance bash script end-to-end
# ---------------------------------------------------------------------------


class TestAcceptanceScriptFull:
    """Run the acceptance shell script as-is — the primary acceptance criterion."""

    def test_acceptance_script_exits_zero(self) -> None:
        """bash acceptance must exit 0."""
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, (
            f"acceptance script failed (exit {result.returncode})\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_acceptance_script_output_has_at_least_four_pass_strings(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        combined = _combined(result)
        count = combined.count("PASS:")
        assert count >= 4, (
            f"Expected >=4 'PASS:' in acceptance output, got {count}.\n{combined}"
        )

    def test_acceptance_script_reports_py_compile_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: py_compile" in _combined(result)

    def test_acceptance_script_reports_imports_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: imports" in _combined(result)

    def test_acceptance_script_reports_bootstrap_dry_run_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: bootstrap --dry-run" in _combined(result)

    def test_acceptance_script_reports_keygen_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: keygen" in _combined(result)

    def test_acceptance_script_reports_help_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: --help" in _combined(result)

    def test_acceptance_script_reports_version_pass(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "PASS: --version" in _combined(result)

    def test_acceptance_script_reports_final_all_passed_message(self) -> None:
        result = subprocess.run(
            ["bash", str(_REPO / "acceptance")],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0
        assert "All acceptance checks passed" in _combined(result)
