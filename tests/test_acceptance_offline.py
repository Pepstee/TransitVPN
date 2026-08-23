"""Tests verifying the acceptance script passes offline.

Acceptance criteria exercised:
  1. ``bash acceptance`` exits 0 when run from the project directory.
  2. stdout contains the exact string ``'All acceptance checks passed.'`` (period included).
  3. No network calls are made during the run.

Criterion 3 is verified by three independent mechanisms:
  A. HTTP/HTTPS proxy blocking — any urllib HTTP call would fail via an invalid proxy.
  B. Socket shim injected via PYTHONPATH / sitecustomize.py — any
     external socket.connect or socket.sendto is logged and re-raised.
     The log file is checked after the run; a non-empty log is a test failure.
  C. Unit-level patches — detect_cgnat(dry_run=True) must never call
     _get_public_ip, _get_local_ip, or _probe_upnp.
"""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

_REPO = Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_acceptance(extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ}
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        ["bash", str(_REPO / "acceptance")],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
        env=env,
    )


def _combined(r: subprocess.CompletedProcess) -> str:
    return r.stdout + r.stderr


# sitecustomize.py injected into every Python subprocess via PYTHONPATH.
# It replaces socket.socket.connect and socket.socket.sendto so that any
# connection to a non-loopback address is both logged (SOCKET_SHIM_LOG env
# var → file) AND raises OSError. The OSError may be swallowed by internal
# except-Exception guards in the code under test; the log file is the
# definitive record of whether any external connection was attempted.
_SOCKET_SHIM = textwrap.dedent("""\
    import socket as _socket
    import os as _os

    _LOG = _os.environ.get("SOCKET_SHIM_LOG", "")
    _real_connect = _socket.socket.connect
    _real_sendto = _socket.socket.sendto

    _LOCAL = frozenset({"127.0.0.1", "::1", "localhost", "0.0.0.0", ""})


    def _record_and_raise(msg):
        if _LOG:
            try:
                with open(_LOG, "a") as _fh:
                    _fh.write(msg + "\\n")
            except Exception:
                pass
        raise OSError(msg)


    def _intercept_connect(self, address):
        host = address[0] if isinstance(address, (tuple, list)) else str(address)
        if isinstance(host, bytes):
            host = host.decode("utf-8", errors="replace")
        if host not in _LOCAL:
            _record_and_raise(f"BLOCKED_EXTERNAL_CONNECT address={address!r}")
        return _real_connect(self, address)


    def _intercept_sendto(self, data, *args):
        # args is (address,) or (flags, address)
        if args:
            last = args[-1]
            if isinstance(last, (tuple, list)):
                host = last[0]
                if isinstance(host, bytes):
                    host = host.decode("utf-8", errors="replace")
                if host not in _LOCAL:
                    _record_and_raise(f"BLOCKED_EXTERNAL_SENDTO address={last!r}")
        return _real_sendto(self, data, *args)


    _socket.socket.connect = _intercept_connect
    _socket.socket.sendto = _intercept_sendto
""")

_INVALID_PROXY = "http://127.0.0.1:1"  # port 1 — nothing listens there


# ---------------------------------------------------------------------------
# Module-level fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def shim_env(tmp_path: Path):
    """Environment dict that injects the socket shim + log file into subprocesses."""
    shim_dir = tmp_path / "shim"
    shim_dir.mkdir()
    log_file = tmp_path / "network.log"
    (shim_dir / "sitecustomize.py").write_text(_SOCKET_SHIM)
    old_pp = os.environ.get("PYTHONPATH", "")
    pythonpath = str(shim_dir) + (":" + old_pp if old_pp else "")
    return {
        "PYTHONPATH": pythonpath,
        "SOCKET_SHIM_LOG": str(log_file),
    }, log_file


# ---------------------------------------------------------------------------
# Criterion 1 — bash acceptance exits 0
# ---------------------------------------------------------------------------


class TestAcceptanceExitsZero:
    def test_bash_acceptance_exits_zero(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0, (
            f"bash acceptance exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_relative_invocation_from_project_dir_exits_zero(self) -> None:
        result = subprocess.run(
            ["bash", "acceptance"],
            capture_output=True,
            text=True,
            cwd=str(_REPO),
        )
        assert result.returncode == 0, (
            f"bash acceptance (relative) exited {result.returncode}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_stdout_not_empty(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert result.stdout.strip() != ""

    def test_stderr_empty_on_clean_run(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert result.stderr.strip() == "", (
            f"Unexpected stderr output:\n{result.stderr}"
        )

    def test_second_sequential_run_also_exits_zero(self) -> None:
        r1 = _run_acceptance()
        r2 = _run_acceptance()
        assert r1.returncode == 0, "first run failed"
        assert r2.returncode == 0, "second run failed"

    def test_all_seven_pass_strings_present(self) -> None:
        # acceptance emits at least 7 "PASS:" echoes (currently 9, including down and status)
        result = _run_acceptance()
        assert result.returncode == 0
        count = result.stdout.count("PASS:")
        assert count >= 7, (
            f"Expected >=7 'PASS:' strings in stdout, got {count}:\n{result.stdout}"
        )

    def test_each_individual_pass_string_is_present(self) -> None:
        expected = [
            "PASS: py_compile",
            "PASS: imports",
            "PASS: --help",
            "PASS: --version",
            "PASS: subcommand up",
            "PASS: subcommand down",
            "PASS: subcommand status",
            "PASS: bootstrap --dry-run",
            "PASS: keygen",
        ]
        result = _run_acceptance()
        assert result.returncode == 0
        for marker in expected:
            assert marker in result.stdout, (
                f"Expected '{marker}' in acceptance stdout.\nstdout:\n{result.stdout}"
            )

    def test_acceptance_stdout_contains_pass_subcommand_down(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "PASS: subcommand down" in result.stdout, (
            f"'PASS: subcommand down' missing from acceptance stdout.\n"
            f"stdout:\n{result.stdout}"
        )

    def test_acceptance_stdout_contains_pass_subcommand_status(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "PASS: subcommand status" in result.stdout, (
            f"'PASS: subcommand status' missing from acceptance stdout.\n"
            f"stdout:\n{result.stdout}"
        )


# ---------------------------------------------------------------------------
# Criterion 2 — output contains 'All acceptance checks passed.'
# ---------------------------------------------------------------------------


class TestAcceptanceSuccessMessage:
    def test_stdout_contains_final_message_with_period(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        assert "All acceptance checks passed." in result.stdout, (
            f"Final success message (with period) missing from stdout.\n"
            f"stdout:\n{result.stdout}"
        )

    def test_final_message_is_not_just_in_stderr(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        # Must be in stdout, not only in stderr
        assert "All acceptance checks passed." in result.stdout

    def test_final_message_appears_as_standalone_line(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        stripped_lines = [ln.strip() for ln in result.stdout.splitlines()]
        assert "All acceptance checks passed." in stripped_lines, (
            f"Expected 'All acceptance checks passed.' as a standalone line.\n"
            f"Lines: {stripped_lines}"
        )

    def test_final_message_is_the_last_output_line(self) -> None:
        result = _run_acceptance()
        assert result.returncode == 0
        non_empty = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
        assert non_empty, "stdout has no non-empty lines"
        assert non_empty[-1] == "All acceptance checks passed.", (
            f"Expected last stdout line == 'All acceptance checks passed.'\n"
            f"Got: {non_empty[-1]!r}"
        )

    def test_period_is_part_of_final_message(self) -> None:
        # "All acceptance checks passed" without period is NOT sufficient
        result = _run_acceptance()
        assert result.returncode == 0
        # The exact echo in the script includes the full stop
        lines = [ln.strip() for ln in result.stdout.splitlines()]
        # There must be NO line that is the message without the period only
        assert "All acceptance checks passed." in lines, (
            "Final message must include the trailing period"
        )


# ---------------------------------------------------------------------------
# Criterion 3A — no network calls: HTTP proxy blocking
# ---------------------------------------------------------------------------


class TestNoNetworkCallsViaProxyBlocking:
    """Verify no HTTP/HTTPS calls are made by blocking them via env-var proxy.

    Python's urllib.request respects http_proxy / https_proxy. Port 1 is
    reserved and accepts no connections, so any urllib.request.urlopen call
    targeting an external URL would raise. The acceptance script uses
    set -euo pipefail, so a subprocess exiting non-zero aborts the script.
    Because the code under test catches its own exceptions (detect_cgnat,
    _get_public_ip all have broad except blocks), the proxy block alone cannot
    guarantee the test is sensitive — but it adds a layer of defence and is
    verified alongside the socket shim tests.
    """

    def test_exits_zero_with_http_proxy_blocked(self) -> None:
        result = _run_acceptance(
            {"http_proxy": _INVALID_PROXY, "HTTP_PROXY": _INVALID_PROXY}
        )
        assert result.returncode == 0, (
            f"Acceptance failed with http_proxy blocked (exit {result.returncode}).\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_exits_zero_with_https_proxy_blocked(self) -> None:
        result = _run_acceptance(
            {"https_proxy": _INVALID_PROXY, "HTTPS_PROXY": _INVALID_PROXY}
        )
        assert result.returncode == 0, (
            f"Acceptance failed with https_proxy blocked (exit {result.returncode}).\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_exits_zero_with_all_proxies_blocked(self) -> None:
        result = _run_acceptance({
            "http_proxy": _INVALID_PROXY,
            "HTTP_PROXY": _INVALID_PROXY,
            "https_proxy": _INVALID_PROXY,
            "HTTPS_PROXY": _INVALID_PROXY,
            "all_proxy": _INVALID_PROXY,
            "ALL_PROXY": _INVALID_PROXY,
        })
        assert result.returncode == 0, (
            f"Acceptance failed with all proxies blocked (exit {result.returncode}).\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_success_message_present_with_proxies_blocked(self) -> None:
        result = _run_acceptance({
            "http_proxy": _INVALID_PROXY,
            "https_proxy": _INVALID_PROXY,
        })
        assert result.returncode == 0
        assert "All acceptance checks passed." in result.stdout


# ---------------------------------------------------------------------------
# Criterion 3B — no network calls: socket shim (log-file verification)
# ---------------------------------------------------------------------------


class TestNoNetworkCallsViaSocketShim:
    """Verify no external socket connections are made.

    The shim (sitecustomize.py injected via PYTHONPATH) intercepts
    socket.socket.connect and socket.socket.sendto for every Python process
    spawned by the acceptance script. Any connection attempt to a non-loopback
    address is written to a log file AND raises OSError.

    We verify:
    a) The acceptance script still exits 0 (no uncaught exception propagated).
    b) The log file is empty (no external connection was even attempted).

    Condition (b) is the strong property: even if the code swallows an
    OSError, the log file proves the attempt happened.
    """

    def test_exits_zero_with_socket_shim(self, shim_env) -> None:
        env_vars, _ = shim_env
        result = _run_acceptance(env_vars)
        assert result.returncode == 0, (
            f"Acceptance failed with socket shim active (exit {result.returncode}).\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_log_file_empty_means_no_external_connections(self, shim_env) -> None:
        env_vars, log_file = shim_env
        result = _run_acceptance(env_vars)
        assert result.returncode == 0
        if log_file.exists():
            logged = log_file.read_text().strip()
            assert not logged, (
                f"Socket shim detected external connection attempts:\n{logged}\n\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )

    def test_no_blocked_connect_marker_in_combined_output(self, shim_env) -> None:
        env_vars, _ = shim_env
        result = _run_acceptance(env_vars)
        combined = _combined(result)
        assert "BLOCKED_EXTERNAL_CONNECT" not in combined, (
            f"An external connect() was blocked during the acceptance run:\n{combined}"
        )

    def test_no_blocked_sendto_marker_in_combined_output(self, shim_env) -> None:
        env_vars, _ = shim_env
        result = _run_acceptance(env_vars)
        combined = _combined(result)
        assert "BLOCKED_EXTERNAL_SENDTO" not in combined, (
            f"An external sendto() was blocked during the acceptance run:\n{combined}"
        )

    def test_success_message_present_with_socket_shim(self, shim_env) -> None:
        env_vars, _ = shim_env
        result = _run_acceptance(env_vars)
        assert result.returncode == 0
        assert "All acceptance checks passed." in result.stdout


# ---------------------------------------------------------------------------
# Criterion 3 combined — proxy + socket shim simultaneously
# ---------------------------------------------------------------------------


class TestNoNetworkCallsCombinedBlocking:
    def test_exits_zero_proxy_and_shim_combined(self, shim_env) -> None:
        env_vars, log_file = shim_env
        env_vars = {
            **env_vars,
            "http_proxy": _INVALID_PROXY,
            "https_proxy": _INVALID_PROXY,
            "HTTP_PROXY": _INVALID_PROXY,
            "HTTPS_PROXY": _INVALID_PROXY,
        }
        result = _run_acceptance(env_vars)
        assert result.returncode == 0, (
            f"Acceptance failed with all network blocked (exit {result.returncode}).\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    def test_log_empty_and_success_message_combined(self, shim_env) -> None:
        env_vars, log_file = shim_env
        env_vars = {**env_vars, "http_proxy": _INVALID_PROXY, "https_proxy": _INVALID_PROXY}
        result = _run_acceptance(env_vars)
        assert result.returncode == 0
        assert "All acceptance checks passed." in result.stdout
        if log_file.exists():
            assert not log_file.read_text().strip(), (
                f"External socket attempts logged despite all blocking:\n{log_file.read_text()}"
            )


# ---------------------------------------------------------------------------
# Criterion 3C — unit level: detect_cgnat(dry_run=True) never touches network
# ---------------------------------------------------------------------------


class TestDetectCgnatDryRunUnit:
    def test_dry_run_does_not_call_get_public_ip(self) -> None:
        from transitvpn import cgnat as _cgnat
        with patch.object(_cgnat, "_get_public_ip") as mock_pub:
            _cgnat.detect_cgnat(dry_run=True)
        mock_pub.assert_not_called()

    def test_dry_run_does_not_call_get_local_ip(self) -> None:
        from transitvpn import cgnat as _cgnat
        with patch.object(_cgnat, "_get_local_ip") as mock_local:
            _cgnat.detect_cgnat(dry_run=True)
        mock_local.assert_not_called()

    def test_dry_run_does_not_call_probe_upnp(self) -> None:
        from transitvpn import cgnat as _cgnat
        with patch.object(_cgnat, "_probe_upnp") as mock_upnp:
            _cgnat.detect_cgnat(dry_run=True)
        mock_upnp.assert_not_called()

    def test_dry_run_returns_unknown_status(self) -> None:
        from transitvpn.cgnat import CgnatStatus, detect_cgnat
        r = detect_cgnat(dry_run=True)
        assert r.status == CgnatStatus.UNKNOWN

    def test_dry_run_returns_none_public_ip(self) -> None:
        from transitvpn.cgnat import detect_cgnat
        r = detect_cgnat(dry_run=True)
        assert r.public_ip is None

    def test_dry_run_returns_none_local_ip(self) -> None:
        from transitvpn.cgnat import detect_cgnat
        r = detect_cgnat(dry_run=True)
        assert r.local_ip is None

    def test_dry_run_details_mention_skipped(self) -> None:
        from transitvpn.cgnat import detect_cgnat
        r = detect_cgnat(dry_run=True)
        combined = " ".join(r.details)
        assert "dry-run" in combined or "skipped" in combined

    def test_dry_run_not_behind_cgnat(self) -> None:
        from transitvpn.cgnat import detect_cgnat
        assert not detect_cgnat(dry_run=True).is_behind_cgnat

    def test_dry_run_with_socket_blocked_still_works(self) -> None:
        import socket
        from transitvpn.cgnat import detect_cgnat

        def _fail_connect(self, *a, **kw):
            raise OSError("BLOCKED in test — socket.connect must not be called for dry_run=True")

        with patch.object(socket.socket, "connect", _fail_connect):
            r = detect_cgnat(dry_run=True)
        # Should return UNKNOWN without error — connect was never called
        from transitvpn.cgnat import CgnatStatus
        assert r.status == CgnatStatus.UNKNOWN

    def test_dry_run_with_urllib_blocked_still_works(self) -> None:
        import urllib.request
        from transitvpn.cgnat import detect_cgnat

        def _fail_urlopen(*a, **kw):
            raise OSError("BLOCKED in test — urlopen must not be called for dry_run=True")

        with patch.object(urllib.request, "urlopen", _fail_urlopen):
            r = detect_cgnat(dry_run=True)
        from transitvpn.cgnat import CgnatStatus
        assert r.status == CgnatStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Structural: acceptance script uses --dry-run for bootstrap
# ---------------------------------------------------------------------------


class TestAcceptanceScriptStructure:
    """Static assertions on the acceptance script text.

    The script must call ``bootstrap --dry-run`` — calling bare ``bootstrap``
    would invoke detect_cgnat(dry_run=False) which fires real network probes.
    """

    def test_acceptance_script_contains_dry_run_flag(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "--dry-run" in content, (
            "acceptance script must pass --dry-run to bootstrap to avoid network probes"
        )

    def test_every_bootstrap_invocation_has_dry_run(self) -> None:
        content = (_REPO / "acceptance").read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "bootstrap" in stripped:
                assert "--dry-run" in stripped, (
                    f"bootstrap called without --dry-run: {stripped!r}\n"
                    "This would trigger real network probes and violate the offline criterion."
                )

    def test_acceptance_script_has_no_pip_install(self) -> None:
        content = (_REPO / "acceptance").read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "pip install" not in stripped, (
                f"acceptance script must not call pip install: {stripped!r}"
            )

    def test_acceptance_script_has_no_pip_module_call(self) -> None:
        content = (_REPO / "acceptance").read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert "-m pip" not in stripped, (
                f"acceptance script must not invoke 'python -m pip': {stripped!r}"
            )

    def test_acceptance_script_has_no_curl_or_wget(self) -> None:
        content = (_REPO / "acceptance").read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not any(cmd in stripped for cmd in ("curl ", "wget ", "fetch ")), (
                f"acceptance script must not use network download tools: {stripped!r}"
            )

    def test_acceptance_script_has_no_apt_get(self) -> None:
        content = (_REPO / "acceptance").read_text()
        assert "apt-get" not in content and "apt " not in content, (
            "acceptance script must not install packages via apt"
        )


# ---------------------------------------------------------------------------
# Structural: CLI wires dry_run=True when --dry-run is passed
# ---------------------------------------------------------------------------


class TestCliBootstrapDryRunWiring:
    """Verify the CLI passes dry_run=True to detect_cgnat when --dry-run is given."""

    def test_bootstrap_dry_run_flag_calls_detect_cgnat_with_dry_run_true(
        self, tmp_path, monkeypatch
    ) -> None:
        from transitvpn.cgnat import CgnatResult, CgnatStatus
        monkeypatch.chdir(tmp_path)
        captured = {}
        from transitvpn import cgnat as _cgnat

        def _spy(**kwargs):
            captured.update(kwargs)
            return CgnatResult(
                status=CgnatStatus.UNKNOWN,
                details=["dry-run: network probes skipped"],
            )

        with patch.object(_cgnat, "detect_cgnat", side_effect=_spy):
            from transitvpn.cli import main
            main(["bootstrap", "--dry-run"])

        assert captured.get("dry_run") is True, (
            f"detect_cgnat was called with {captured!r}, expected dry_run=True"
        )

    def test_bootstrap_without_dry_run_calls_detect_cgnat_with_dry_run_false(
        self, tmp_path, monkeypatch
    ) -> None:
        from transitvpn.cgnat import CgnatResult, CgnatStatus
        monkeypatch.chdir(tmp_path)
        captured = {}
        from transitvpn import cgnat as _cgnat

        def _spy(**kwargs):
            captured.update(kwargs)
            return CgnatResult(
                status=CgnatStatus.NOT_BEHIND_CGNAT,
                public_ip="1.2.3.4",
                local_ip="192.168.0.1",
                details=[],
            )

        with patch.object(_cgnat, "detect_cgnat", side_effect=_spy):
            from transitvpn.cli import main
            main(["bootstrap"])

        assert captured.get("dry_run") is False, (
            f"detect_cgnat was called with {captured!r}, expected dry_run=False"
        )


# ---------------------------------------------------------------------------
# Structural: generate_keys uses no network
# ---------------------------------------------------------------------------


class TestGenerateKeysNoNetwork:
    def test_generate_keys_with_socket_blocked(self) -> None:
        import socket
        from transitvpn.keygen import generate_keys

        def _fail_connect(self, *a, **kw):
            raise OSError("BLOCKED in test")

        with patch.object(socket.socket, "connect", _fail_connect):
            keys = generate_keys()

        assert keys.vless_uuid
        assert keys.reality_private_key
        assert keys.reality_public_key
        assert keys.ss_password

    def test_generate_keys_with_urlopen_blocked(self) -> None:
        import urllib.request
        from transitvpn.keygen import generate_keys

        def _fail_urlopen(*a, **kw):
            raise OSError("BLOCKED in test")

        with patch.object(urllib.request, "urlopen", _fail_urlopen):
            keys = generate_keys()

        assert keys.vless_uuid
        assert keys.reality_private_key != keys.reality_public_key
