"""Real tunnel lifecycle tests using a long-lived fake process.

TRANSITVPN_PROXY_BIN is set to 'sys.executable -c import time; time.sleep(30)'
to inject a process that lives long enough to exercise start/stop/status without
requiring the xray binary.

start_tunnel splits the env-var on whitespace (maxsplit=2) and appends
'-config <path>', which the sleep script silently ignores.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from transitvpn.tunnel import get_status, start_tunnel, stop_tunnel

_FAKE_BIN = sys.executable + " -c " + "import time; time.sleep(30)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _process_is_alive(pid: int) -> bool:
    """True if process is running (not dead, not a zombie child of this process).

    On Linux, os.kill(zombie, 0) succeeds — zombies look alive.  We use
    os.waitpid(WNOHANG) to reap our own zombie children, which makes them
    disappear immediately instead of appearing alive for up to 5 seconds.
    """
    try:
        ret, _ = os.waitpid(pid, os.WNOHANG)
        # ret == 0 → child still running; ret == pid → zombie reaped → dead
        return ret != pid
    except ChildProcessError:
        # pid is not a direct child of this process
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False


def _wait_until_dead(pid: int, timeout: float = 5.0) -> bool:
    """Return True once the process is gone or has been reaped as a zombie."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not _process_is_alive(pid):
            return True
        time.sleep(0.05)
    return False


def _dead_pid() -> int:
    """Spawn a quick-exit child, wait for it, and return its (now-dead) PID."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "pass"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    dead = proc.pid
    proc.wait()  # reap — PID is now fully gone
    return dead


def _kill_for_cleanup(state_dir: str) -> None:
    """Fast SIGKILL + reap for finally-block cleanup.

    Use ONLY in tests that are not testing stop_tunnel behaviour — this
    bypasses stop_tunnel's graceful shutdown and avoids the 5-second zombie
    wait that occurs when stop_tunnel is called in-process.
    """
    pid_file = Path(state_dir) / "tunnel.pid"
    if not pid_file.exists():
        return
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGKILL)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
    except (ValueError, OSError, ProcessLookupError):
        pass
    pid_file.unlink(missing_ok=True)


def _run_cli(cmd: str, workdir: Path, extra_env: dict) -> subprocess.CompletedProcess:
    env = {**os.environ, **extra_env}
    return subprocess.run(
        [sys.executable, "-m", "transitvpn", cmd],
        capture_output=True,
        text=True,
        cwd=str(workdir),
        env=env,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_bin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRANSITVPN_PROXY_BIN", _FAKE_BIN)


@pytest.fixture
def state_dir(tmp_path: Path) -> str:
    return str(tmp_path / "state")


@pytest.fixture
def config_file(tmp_path: Path) -> str:
    path = tmp_path / "tunnel-cfg.json"
    path.write_text(json.dumps({"fake": "config"}))
    return str(path)


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    """Working directory with state/xray-server.json pre-created."""
    state = tmp_path / "state"
    state.mkdir()
    (state / "xray-server.json").write_text(json.dumps({"server": "fake"}))
    return tmp_path


@pytest.fixture
def proxy_env() -> dict:
    return {"TRANSITVPN_PROXY_BIN": _FAKE_BIN}


# ---------------------------------------------------------------------------
# start_tunnel()
# ---------------------------------------------------------------------------


class TestStartTunnel:
    def test_returns_pid_and_no_error(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None, f"unexpected error: {err}"
            assert pid is not None
        finally:
            _kill_for_cleanup(state_dir)

    def test_pid_is_positive_integer(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None
            assert isinstance(pid, int) and pid > 0
        finally:
            _kill_for_cleanup(state_dir)

    def test_pid_file_created_in_state_dir(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_tunnel(config_file, state_dir)
        try:
            assert (Path(state_dir) / "tunnel.pid").exists(), "tunnel.pid not created"
        finally:
            _kill_for_cleanup(state_dir)

    def test_pid_file_contains_returned_pid(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None
            stored = int((Path(state_dir) / "tunnel.pid").read_text().strip())
            assert stored == pid
        finally:
            _kill_for_cleanup(state_dir)

    def test_state_dir_created_automatically(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        assert not Path(state_dir).exists()
        start_tunnel(config_file, state_dir)
        try:
            assert Path(state_dir).exists()
        finally:
            _kill_for_cleanup(state_dir)

    def test_process_is_actually_running_after_start(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None
            assert _process_is_alive(pid), f"process {pid} not alive after start"
        finally:
            _kill_for_cleanup(state_dir)

    def test_missing_config_returns_none_and_error(
        self, fake_bin: None, state_dir: str, tmp_path: Path
    ) -> None:
        pid, err = start_tunnel(str(tmp_path / "no_such_file.json"), state_dir)
        assert pid is None
        assert err is not None
        assert "config not found" in err

    def test_invalid_json_config_returns_none_and_error(
        self, fake_bin: None, state_dir: str, tmp_path: Path
    ) -> None:
        bad_cfg = tmp_path / "bad.json"
        bad_cfg.write_text("{not valid json")
        pid, err = start_tunnel(str(bad_cfg), state_dir)
        assert pid is None
        assert err is not None
        assert "invalid config JSON" in err

    def test_nonexistent_binary_returns_none_and_error(
        self, monkeypatch: pytest.MonkeyPatch, config_file: str, state_dir: str
    ) -> None:
        monkeypatch.setenv("TRANSITVPN_PROXY_BIN", "/no/such/binary/does/not/exist")
        pid, err = start_tunnel(config_file, state_dir)
        assert pid is None
        assert err is not None
        assert "not found" in err

    def test_immediately_exiting_proxy_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, config_file: str, state_dir: str
    ) -> None:
        # A proxy that dies on startup (bad config / port in use) must NOT be
        # reported as a running tunnel.
        monkeypatch.setenv(
            "TRANSITVPN_PROXY_BIN", sys.executable + " -c " + "import sys; sys.exit(3)"
        )
        pid, err = start_tunnel(config_file, state_dir)
        assert pid is None, "dead proxy must not yield a pid"
        assert err is not None
        assert "exited immediately" in err
        assert not (Path(state_dir) / "tunnel.pid").exists(), (
            "no pid file should remain for a proxy that failed to start"
        )

    def test_double_start_returns_error(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid1, err1 = start_tunnel(config_file, state_dir)
        try:
            assert err1 is None, f"first start failed: {err1}"
            assert pid1 is not None

            pid2, err2 = start_tunnel(config_file, state_dir)
            assert pid2 is None, "second start must return None for pid"
            assert err2 is not None, "second start must return an error string"
            assert "already running" in err2, (
                f"error must mention 'already running', got: {err2!r}"
            )
            # The first process must still be alive — start_tunnel must not kill it.
            assert _process_is_alive(pid1), (
                f"first process (pid={pid1}) died after second start_tunnel call"
            )
        finally:
            _kill_for_cleanup(state_dir)


# ---------------------------------------------------------------------------
# stop_tunnel()
# ---------------------------------------------------------------------------


class TestStopTunnel:
    def test_stop_kills_the_process(self, fake_bin: None, config_file: str, state_dir: str) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        assert err is None
        stop_tunnel(state_dir)
        # _process_is_alive reaps our zombie child via waitpid, so this is fast
        assert _wait_until_dead(pid), f"process {pid} still alive after stop"

    def test_stop_removes_pid_file(self, fake_bin: None, config_file: str, state_dir: str) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        assert not (Path(state_dir) / "tunnel.pid").exists()

    def test_stop_without_state_dir_does_not_raise(self, state_dir: str) -> None:
        assert not Path(state_dir).exists()
        stop_tunnel(state_dir)

    def test_stop_without_pid_file_does_not_raise(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        stop_tunnel(state_dir)

    def test_stop_with_stale_pid_removes_pid_file(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        (Path(state_dir) / "tunnel.pid").write_text(str(_dead_pid()))
        stop_tunnel(state_dir)
        assert not (Path(state_dir) / "tunnel.pid").exists()

    def test_stop_with_corrupt_pid_file_does_not_raise(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        (Path(state_dir) / "tunnel.pid").write_text("not-an-integer\n")
        stop_tunnel(state_dir)
        assert not (Path(state_dir) / "tunnel.pid").exists()

    def test_double_stop_is_idempotent(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        stop_tunnel(state_dir)  # pid file gone — must not raise


# ---------------------------------------------------------------------------
# get_status()
# ---------------------------------------------------------------------------


class TestGetStatus:
    def test_not_running_when_no_state_dir(self, state_dir: str) -> None:
        running, pid = get_status(state_dir)
        assert running is False
        assert pid is None

    def test_not_running_when_no_pid_file(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        running, pid = get_status(state_dir)
        assert running is False
        assert pid is None

    def test_running_true_after_start(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None
            running, _ = get_status(state_dir)
            assert running is True
        finally:
            _kill_for_cleanup(state_dir)

    def test_status_pid_matches_start_pid(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_pid, err = start_tunnel(config_file, state_dir)
        try:
            assert err is None
            _, status_pid = get_status(state_dir)
            assert status_pid == start_pid
        finally:
            _kill_for_cleanup(state_dir)

    def test_not_running_after_stop(self, fake_bin: None, config_file: str, state_dir: str) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        running, _ = get_status(state_dir)
        assert running is False

    def test_not_running_with_stale_pid(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        (Path(state_dir) / "tunnel.pid").write_text(str(_dead_pid()))
        running, _ = get_status(state_dir)
        assert running is False

    def test_not_running_with_corrupt_pid_file(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        (Path(state_dir) / "tunnel.pid").write_text("garbage\n")
        running, pid = get_status(state_dir)
        assert running is False
        assert pid is None


# ---------------------------------------------------------------------------
# Integration: full lifecycle via module functions
# ---------------------------------------------------------------------------


class TestTunnelLifecycle:
    def test_full_start_stop_status_round_trip(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        pid, err = start_tunnel(config_file, state_dir)
        assert err is None, f"start failed: {err}"
        assert pid is not None

        assert (Path(state_dir) / "tunnel.pid").exists()

        running, status_pid = get_status(state_dir)
        assert running is True
        assert status_pid == pid

        stop_tunnel(state_dir)

        running, _ = get_status(state_dir)
        assert running is False

        assert not (Path(state_dir) / "tunnel.pid").exists()

        assert _wait_until_dead(pid, timeout=1.0)

    def test_double_stop_is_idempotent(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        stop_tunnel(state_dir)

    def test_pid_file_absent_after_stop(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        assert not (Path(state_dir) / "tunnel.pid").exists()


# ---------------------------------------------------------------------------
# CLI subcommands via real subprocesses with fake proxy
# ---------------------------------------------------------------------------


class TestCLILifecycle:
    """CLI-level: up/down/status via subprocesses.

    Processes spawned by CLI subcommands are children of transient subprocesses
    that immediately exit, so they get re-parented to init.  Init auto-reaps
    them — no zombie issue, stop_tunnel is fast.
    """

    def test_up_exits_zero_with_valid_config(self, workdir: Path, proxy_env: dict) -> None:
        result = _run_cli("up", workdir, proxy_env)
        try:
            assert result.returncode == 0, f"up failed:\n{result.stdout}{result.stderr}"
        finally:
            _run_cli("down", workdir, proxy_env)

    def test_up_creates_pid_file(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        try:
            assert (workdir / "state" / "tunnel.pid").exists(), "tunnel.pid not created by up"
        finally:
            _run_cli("down", workdir, proxy_env)

    def test_up_output_contains_pid(self, workdir: Path, proxy_env: dict) -> None:
        result = _run_cli("up", workdir, proxy_env)
        try:
            assert "pid=" in result.stdout, f"pid not in up output: {result.stdout!r}"
        finally:
            _run_cli("down", workdir, proxy_env)

    def test_status_returns_running_after_up(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        try:
            result = _run_cli("status", workdir, proxy_env)
            assert "running" in result.stdout
            assert "not running" not in result.stdout
        finally:
            _run_cli("down", workdir, proxy_env)

    def test_down_kills_process_and_removes_pid(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        pid_file = workdir / "state" / "tunnel.pid"
        pid = int(pid_file.read_text().strip())
        _run_cli("down", workdir, proxy_env)
        assert not pid_file.exists(), "tunnel.pid still present after down"
        assert _wait_until_dead(pid), f"process {pid} still alive after down"

    def test_status_returns_not_running_after_down(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        _run_cli("down", workdir, proxy_env)
        result = _run_cli("status", workdir, proxy_env)
        assert "not running" in result.stdout

    def test_double_down_exits_zero_both_times(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        r1 = _run_cli("down", workdir, proxy_env)
        r2 = _run_cli("down", workdir, proxy_env)
        assert r1.returncode == 0
        assert r2.returncode == 0

    def test_double_down_both_print_down_prefix(self, workdir: Path, proxy_env: dict) -> None:
        _run_cli("up", workdir, proxy_env)
        r1 = _run_cli("down", workdir, proxy_env)
        r2 = _run_cli("down", workdir, proxy_env)
        assert "down:" in r1.stdout
        assert "down:" in r2.stdout

    def test_down_exits_zero_when_no_tunnel_running(self, workdir: Path, proxy_env: dict) -> None:
        result = _run_cli("down", workdir, proxy_env)
        assert result.returncode == 0
