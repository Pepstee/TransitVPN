"""Process lifecycle checks and pinned-Xray restart acceptance.

Most tests inject a fake executable to exercise process management. The real
restart acceptance uses the pinned binary and verifies application data.
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

from transitvpn import tunnel
from transitvpn.tunnel import get_status, start_tunnel, stop_tunnel


def _write_test_binary(path: Path, body: str = "import time; time.sleep(30)") -> str:
    # The exact launched script stays in argv; no exec-sleep wrapper can pass
    # the verified-launch identity check.
    path.write_text(f"#!{sys.executable}\n" + body + "\n")
    path.chmod(0o700)
    return str(path)


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


def _signal_test_spawned_process(pid: int, signum: int) -> None:
    """Signal only the exact test-created incarnation through its pidfd."""
    pidfd = os.pidfd_open(pid, 0)
    try:
        signal.pidfd_send_signal(pidfd, signum)
    finally:
        os.close(pidfd)


def _kill_for_cleanup(state_dir: str) -> None:
    """Use the production identity-bound stop path for a test-owned child."""
    stop_tunnel(state_dir)


def _run_cli(cmd: str, workdir: Path, proxy_binary: str) -> subprocess.CompletedProcess:
    # Inject in the child interpreter, never through a production trust bypass.
    harness = (
        "import sys; import transitvpn.tunnel as tunnel; "
        "tunnel.verify_binary = lambda binary: (sys.argv[1], None); "
        "from transitvpn.cli import main; raise SystemExit(main(sys.argv[2:]))"
    )
    return subprocess.run(
        [sys.executable, "-c", harness, proxy_binary, cmd],
        capture_output=True,
        text=True,
        cwd=str(workdir),
        env={**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1])},
        timeout=15,
        check=False,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_bin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable = _write_test_binary(tmp_path / "test-proxy")
    monkeypatch.setattr(tunnel, "verify_binary", lambda binary: (executable, None))


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
def proxy_binary(tmp_path: Path) -> str:
    return _write_test_binary(tmp_path / "cli-test-proxy")


# ---------------------------------------------------------------------------
# start_tunnel()
# ---------------------------------------------------------------------------


class TestStartTunnel:
    def test_invocation_rejects_verified_path_as_unrelated_argument(
        self, tmp_path: Path, config_file: str
    ) -> None:
        executable = str(Path(_write_test_binary(tmp_path / "proxy")).resolve())
        interpreter = str(Path(sys.executable).resolve())
        argv = [interpreter, "-c", "pass", executable, "run", "-config", config_file]
        assert not tunnel._invocation_matches(
            executable,
            str(Path(config_file).resolve()),
            interpreter,
            argv,
        )

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
            stored = json.loads((Path(state_dir) / "tunnel.pid").read_text())["pid"]
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
        monkeypatch.setattr(
            tunnel, "verify_binary", lambda binary: ("/no/such/binary/does/not/exist", None)
        )
        pid, err = start_tunnel(config_file, state_dir)
        assert pid is None
        assert err is not None
        assert "not found" in err

    def test_unverified_binary_returns_error_without_spawning(
        self, monkeypatch: pytest.MonkeyPatch, config_file: str, state_dir: str
    ) -> None:
        def reject(binary: str) -> None:
            raise RuntimeError("unverified Xray binary")

        def unexpected_spawn(*args, **kwargs):
            pytest.fail("a rejected binary must never be executed")

        monkeypatch.setattr(tunnel, "verify_binary", reject)
        monkeypatch.setattr(tunnel.subprocess, "Popen", unexpected_spawn)
        pid, err = start_tunnel(config_file, state_dir)
        assert pid is None
        assert err == "unverified Xray binary"
        assert not (Path(state_dir) / "tunnel.pid").exists()

    def test_immediately_exiting_proxy_returns_error(
        self, monkeypatch: pytest.MonkeyPatch, config_file: str, state_dir: str,
        tmp_path: Path,
    ) -> None:
        # A proxy that dies on startup (bad config / port in use) must NOT be
        # reported as a running tunnel.
        executable = _write_test_binary(tmp_path / "exiting-proxy", "raise SystemExit(3)")
        monkeypatch.setattr(tunnel, "verify_binary", lambda binary: (executable, None))
        real_popen = subprocess.Popen

        def spawn_exiting_proxy(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            # Observe the real exit before returning: scheduler load must not
            # turn this error-path test into a startup timing benchmark.
            assert proc.wait(timeout=5) == 3
            return proc

        monkeypatch.setattr(tunnel.subprocess, "Popen", spawn_exiting_proxy)
        pid, err = start_tunnel(config_file, state_dir)
        assert pid is None, "dead proxy must not yield a pid"
        assert err is not None
        assert "exited immediately" in err
        assert not (Path(state_dir) / "tunnel.pid").exists(), (
            "no pid file should remain for a proxy that failed to start"
        )

    def test_identity_mismatch_stops_new_child_and_writes_no_state(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spawned: list[subprocess.Popen] = []
        real_popen = subprocess.Popen

        def capture_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            spawned.append(child)
            return child

        real_identity = tunnel._read_live_identity

        def mismatched_identity(pid: int, pidfd: int):
            result = real_identity(pid, pidfd)
            assert result is not None
            identity, argv = result
            return identity, [*argv, "unexpected-argument"]

        monkeypatch.setattr(tunnel.subprocess, "Popen", capture_popen)
        monkeypatch.setattr(tunnel, "_read_live_identity", mismatched_identity)
        pid, error = start_tunnel(config_file, state_dir)
        assert pid is None
        assert error and "did not match the verified invocation" in error
        assert "stopped safely" in error
        assert spawned and spawned[0].poll() is not None
        assert not (Path(state_dir) / "tunnel.pid").exists()

    def test_state_write_failure_stops_child_and_preserves_prior_record(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        prior_pid, prior_error = start_tunnel(config_file, state_dir)
        assert prior_error is None and prior_pid is not None
        pid_file = Path(state_dir) / "tunnel.pid"
        prior_record = pid_file.read_bytes()
        assert stop_tunnel(state_dir) is None
        assert _wait_until_dead(prior_pid)
        pid_file.write_bytes(prior_record)

        spawned: list[subprocess.Popen] = []
        real_popen = subprocess.Popen

        def capture_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            spawned.append(child)
            return child

        def fail_write(*_args, **_kwargs):
            raise OSError("simulated state write failure")

        monkeypatch.setattr(tunnel.subprocess, "Popen", capture_popen)
        monkeypatch.setattr(tunnel, "_write_record_atomic", fail_write)
        pid, error = start_tunnel(config_file, state_dir)
        assert pid is None
        assert error and "state record could not be saved" in error
        assert "stopped safely" in error
        assert spawned and spawned[0].poll() is not None
        assert pid_file.read_bytes() == prior_record

    def test_pidfd_open_failure_reports_live_untracked_child_truthfully(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        spawned: list[subprocess.Popen] = []
        real_popen = subprocess.Popen

        def capture_popen(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            spawned.append(child)
            return child

        def refuse_pidfd(_pid: int, _flags: int):
            raise PermissionError("simulated pidfd_open denial")

        monkeypatch.setattr(tunnel.subprocess, "Popen", capture_popen)
        monkeypatch.setattr(tunnel.os, "pidfd_open", refuse_pidfd)
        pid, error = start_tunnel(config_file, state_dir)
        try:
            assert pid is None
            assert error and "remains alive but untracked" in error
            assert "no signal was sent" in error
            assert spawned and spawned[0].poll() is None
            assert not (Path(state_dir) / "tunnel.pid").exists()
        finally:
            if spawned and spawned[0].poll() is None:
                spawned[0].terminate()
                spawned[0].wait(timeout=5)

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
    def test_live_state_transition_with_same_start_ticks_keeps_identity(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pid, error = start_tunnel(config_file, state_dir)
        assert error is None and pid is not None
        pidfd = os.pidfd_open(pid, 0)
        record = json.loads((Path(state_dir) / "tunnel.pid").read_text())
        real_read_start = tunnel._read_proc_start
        states = iter([("R", record["start_time_ticks"]), ("S", record["start_time_ticks"])])

        def state_transition(_pid: int):
            try:
                return next(states)
            except StopIteration:
                return real_read_start(_pid)

        monkeypatch.setattr(tunnel, "_read_proc_start", state_transition)
        try:
            assert tunnel._identity_matches(record, pidfd)
        finally:
            os.close(pidfd)
            monkeypatch.setattr(tunnel, "_read_proc_start", real_read_start)
            assert stop_tunnel(state_dir) is None

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

    @pytest.mark.parametrize("legacy_pid", ["0", "-17", "not-an-integer"])
    def test_stop_preserves_untrusted_pid_without_signaling(
        self,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
        legacy_pid: str,
    ) -> None:
        Path(state_dir).mkdir(parents=True)
        pid_file = Path(state_dir) / "tunnel.pid"
        pid_file.write_text(legacy_pid)
        sends: list[tuple[int, int]] = []
        monkeypatch.setattr(
            tunnel.signal,
            "pidfd_send_signal",
            lambda pidfd, sig: sends.append((pidfd, sig)),
        )
        assert get_status(state_dir) == (False, None)
        error = stop_tunnel(state_dir)
        assert error and "refusing to signal" in error
        assert pid_file.read_text() == legacy_pid
        assert sends == []

    def test_stop_preserves_corrupt_pid_file_without_signaling(
        self, state_dir: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        Path(state_dir).mkdir(parents=True)
        pid_file = Path(state_dir) / "tunnel.pid"
        pid_file.write_text("{broken\n")
        sends: list[tuple[int, int]] = []
        monkeypatch.setattr(
            tunnel.signal,
            "pidfd_send_signal",
            lambda pidfd, sig: sends.append((pidfd, sig)),
        )
        error = stop_tunnel(state_dir)
        assert error and "state preserved" in error
        assert pid_file.read_text() == "{broken\n"
        assert sends == []

    def test_unrelated_live_child_is_not_owned_or_signaled(
        self,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        Path(state_dir).mkdir(parents=True)
        pid_file = Path(state_dir) / "tunnel.pid"
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        sends: list[tuple[int, int]] = []
        monkeypatch.setattr(
            tunnel.signal,
            "pidfd_send_signal",
            lambda pidfd, sig: sends.append((pidfd, sig)),
        )
        try:
            pid_file.write_text(str(child.pid))
            assert get_status(state_dir) == (False, None)
            error = stop_tunnel(state_dir)
            assert error and "state preserved" in error
            assert sends == []
            assert child.poll() is None
        finally:
            child.terminate()
            child.wait(timeout=5)

    def test_term_lookup_race_preserves_concurrently_changed_record(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pid, error = start_tunnel(config_file, state_dir)
        assert error is None and pid is not None
        pid_file = Path(state_dir) / "tunnel.pid"
        original_send = signal.pidfd_send_signal
        pidfd = os.pidfd_open(pid, 0)

        def exit_and_change_record(_pidfd: int, _signum: int) -> None:
            pid_file.write_text("concurrent-owner-state\n")
            raise ProcessLookupError

        monkeypatch.setattr(tunnel.signal, "pidfd_send_signal", exit_and_change_record)
        try:
            refusal = stop_tunnel(state_dir)
            assert refusal and "changed concurrently" in refusal
            assert pid_file.read_text() == "concurrent-owner-state\n"
        finally:
            if not tunnel._pidfd_exited(pidfd):
                original_send(pidfd, signal.SIGKILL)
            os.close(pidfd)

    def test_kill_lookup_race_preserves_concurrently_changed_record(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_file: str,
        state_dir: str,
        tmp_path: Path,
    ) -> None:
        ready_file = tmp_path / "handler-ready"
        executable = _write_test_binary(
            tmp_path / "ignores-term",
            "import signal, time\n"
            "from pathlib import Path\n"
            f"signal.signal(signal.SIGTERM, lambda *_: None)\nPath({str(ready_file)!r}).write_text('ready')\n"
            "time.sleep(30)",
        )
        monkeypatch.setattr(tunnel, "verify_binary", lambda _binary: (executable, None))
        pid, error = start_tunnel(config_file, state_dir)
        assert error is None and pid is not None
        deadline = time.monotonic() + 2.0
        while not ready_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready_file.exists(), "TERM handler did not become ready"
        pid_file = Path(state_dir) / "tunnel.pid"
        pidfd = os.pidfd_open(pid, 0)
        original_send = signal.pidfd_send_signal
        monkeypatch.setattr(tunnel, "_STOP_GRACE_SECONDS", 0.0)

        def race_kill(handle: int, signum: int) -> None:
            if signum == signal.SIGKILL:
                pid_file.write_text("concurrent-owner-state\n")
                raise ProcessLookupError
            original_send(handle, signum)

        monkeypatch.setattr(tunnel.signal, "pidfd_send_signal", race_kill)
        try:
            refusal = stop_tunnel(state_dir)
            assert refusal and "changed concurrently" in refusal
            assert pid_file.read_text() == "concurrent-owner-state\n"
        finally:
            if not tunnel._pidfd_exited(pidfd):
                original_send(pidfd, signal.SIGKILL)
            os.close(pidfd)

    def test_reused_pid_with_different_start_time_is_not_signaled(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pid_file = Path(state_dir) / "tunnel.pid"
        child_pid, error = start_tunnel(config_file, state_dir)
        assert error is None and child_pid is not None
        sends: list[tuple[int, int]] = []
        original_send = signal.pidfd_send_signal
        monkeypatch.setattr(
            tunnel.signal,
            "pidfd_send_signal",
            lambda pidfd, sig: sends.append((pidfd, sig)),
        )
        pidfd = os.pidfd_open(child_pid, 0)
        try:
            record = json.loads(pid_file.read_text())
            record["start_time_ticks"] += 1
            pid_file.write_text(json.dumps(record))
            assert get_status(state_dir) == (False, None)
            error = stop_tunnel(state_dir)
            assert error and "identity does not match" in error
            assert sends == []
        finally:
            if not tunnel._pidfd_exited(pidfd):
                original_send(pidfd, signal.SIGKILL)
            os.close(pidfd)
            assert _wait_until_dead(child_pid)

    def test_pidfd_pins_original_process_across_pre_signal_replacement(
        self,
        fake_bin: None,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pid, error = start_tunnel(config_file, state_dir)
        assert error is None and pid is not None
        real_send = signal.pidfd_send_signal
        replacement: subprocess.Popen | None = None
        requested: list[int] = []

        def replace_before_signal(pidfd: int, signum: int) -> None:
            nonlocal replacement
            requested.append(signum)
            if signum == signal.SIGTERM and replacement is None:
                # Simulate exit after identity validation but before TERM. The
                # already-open pidfd remains bound to the original instance.
                real_send(pidfd, signal.SIGKILL)
                assert tunnel._wait_pidfd_exit(pidfd, 2.0)
                replacement = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            real_send(pidfd, signum)

        monkeypatch.setattr(tunnel.signal, "pidfd_send_signal", replace_before_signal)
        try:
            assert stop_tunnel(state_dir) is None
            assert requested == [signal.SIGTERM]
            assert replacement is not None and replacement.poll() is None
        finally:
            if replacement is not None:
                replacement.terminate()
                replacement.wait(timeout=5)

    def test_stop_refuses_force_kill_after_process_exec_replacement(
        self,
        monkeypatch: pytest.MonkeyPatch,
        config_file: str,
        state_dir: str,
        tmp_path: Path,
    ) -> None:
        executable = _write_test_binary(
            tmp_path / "exec-on-term",
            "import os, signal, sys, time\n"
            "def on_term(_signum, _frame):\n"
            "    os.execv(sys.executable, [sys.executable, '-c', 'import time; time.sleep(30)'])\n"
            "signal.signal(signal.SIGTERM, on_term)\n"
            "time.sleep(30)",
        )
        monkeypatch.setattr(tunnel, "verify_binary", lambda _binary: (executable, None))
        pid, error = start_tunnel(config_file, state_dir)
        assert error is None and pid is not None
        pidfd = os.pidfd_open(pid, 0)
        monkeypatch.setattr(tunnel, "_STOP_GRACE_SECONDS", 0.1)
        real_send = signal.pidfd_send_signal
        sent: list[int] = []

        def capture_signals(handle: int, signum: int) -> None:
            sent.append(signum)
            real_send(handle, signum)

        monkeypatch.setattr(tunnel.signal, "pidfd_send_signal", capture_signals)
        pid_file = Path(state_dir) / "tunnel.pid"
        try:
            error = stop_tunnel(state_dir)
            assert error and "identity changed" in error
            assert sent == [signal.SIGTERM]
            assert pid_file.exists()
        finally:
            if not tunnel._pidfd_exited(pidfd):
                real_send(pidfd, signal.SIGKILL)
            os.close(pidfd)

    def test_double_stop_is_idempotent(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        start_tunnel(config_file, state_dir)
        stop_tunnel(state_dir)
        stop_tunnel(state_dir)  # pid file gone — must not raise


# ---------------------------------------------------------------------------
# get_status()
# ---------------------------------------------------------------------------


class TestGetStatusNoStateDir:
    def test_not_running_when_no_state_dir(self, state_dir: str) -> None:
        running, pid = get_status(state_dir)
        assert running is False
        assert pid is None


class TestForegroundService:
    def test_invalid_xray_config_is_rejected_before_spawn(
        self,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        calls: list[bool] = []

        def invalid_config(_configs: object, *, binary: str) -> dict[str, str]:
            raise RuntimeError("private Xray diagnostic")

        monkeypatch.setattr(tunnel, "validate_configs", invalid_config)
        monkeypatch.setattr(
            tunnel,
            "start_tunnel",
            lambda *_args, **_kwargs: calls.append(True),
        )

        result = tunnel.serve_foreground(config_file, state_dir)

        assert result == (1, "tunnel configuration failed pinned Xray validation")
        assert calls == []

    def test_unverified_process_is_never_signaled(
        self,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        sends: list[int] = []
        record = {"pid": child.pid}
        monkeypatch.setattr(tunnel, "validate_configs", lambda *_args, **_kwargs: {})
        monkeypatch.setattr(
            tunnel,
            "start_tunnel",
            lambda *_args, **_kwargs: (child.pid, None),
        )
        monkeypatch.setattr(tunnel, "_read_record", lambda _path: (record, b"test-record"))
        monkeypatch.setattr(tunnel, "_identity_matches", lambda *_args: False)
        monkeypatch.setattr(
            tunnel, "_signal_pidfd", lambda _pidfd, signum: sends.append(signum)
        )
        try:
            result = tunnel.serve_foreground(config_file, state_dir)
            assert result == (1, "foreground process identity could not be verified")
            assert sends == []
            assert child.poll() is None
        finally:
            child.terminate()
            child.wait(timeout=5)

    def test_unexpected_owned_child_exit_is_failure_and_reaped(
        self,
        tmp_path: Path,
        config_file: str,
        state_dir: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        executable = _write_test_binary(
            tmp_path / "short-lived-proxy", "import time; time.sleep(0.45)"
        )
        monkeypatch.setattr(tunnel, "verify_binary", lambda _binary: (executable, None))
        monkeypatch.setattr(tunnel, "validate_configs", lambda *_args, **_kwargs: {})
        started: list[int] = []
        real_start = tunnel.start_tunnel

        def capture_start(*args: object, **kwargs: object) -> tuple[int | None, str | None]:
            result = real_start(*args, **kwargs)
            if result[0] is not None:
                started.append(result[0])
            return result

        monkeypatch.setattr(tunnel, "start_tunnel", capture_start)
        result = tunnel.serve_foreground(config_file, state_dir)

        assert result == (1, "managed tunnel exited unexpectedly")
        assert started
        assert not (Path(state_dir) / "tunnel.pid").exists()
        assert not _process_is_alive(started[0])

    @pytest.mark.parametrize("changed_record", [False, True])
    def test_requested_stop_cleans_owned_child_and_restores_handlers(
        self,
        tmp_path: Path,
        config_file: str,
        state_dir: str,
        changed_record: bool,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        import threading

        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        state_path = Path(state_dir)
        state_path.mkdir(parents=True, exist_ok=True)
        pid_path = state_path / "tunnel.pid"
        initial_record = b"verified-test-record\n"
        pid_path.write_bytes(initial_record)
        record = {"pid": child.pid}
        previous_handlers = {
            signal.SIGTERM: signal.getsignal(signal.SIGTERM),
            signal.SIGINT: signal.getsignal(signal.SIGINT),
        }
        handlers_installed = threading.Event()
        real_signal = signal.signal

        def record_handler(signum: int, handler: object) -> object:
            previous = real_signal(signum, handler)
            if signum == signal.SIGINT and callable(handler):
                handlers_installed.set()
            return previous

        monkeypatch.setattr(tunnel.signal, "signal", record_handler)
        monkeypatch.setattr(tunnel, "validate_configs", lambda *_args, **_kwargs: {})
        monkeypatch.setattr(
            tunnel,
            "start_tunnel",
            lambda *_args, **_kwargs: (child.pid, None),
        )
        monkeypatch.setattr(
            tunnel,
            "_read_record",
            lambda _path: (record, initial_record),
        )
        monkeypatch.setattr(tunnel, "_identity_matches", lambda *_args: True)
        if changed_record:
            def preserve_replacement(path: Path, _original: bytes) -> bool:
                path.write_bytes(b"replacement-state\n")
                return False

            monkeypatch.setattr(tunnel, "_remove_record_if_unchanged", preserve_replacement)

        request_result: list[str] = []

        def request_stop() -> None:
            if not handlers_installed.wait(5):
                request_result.append("handler-not-installed")
                return
            os.kill(os.getpid(), signal.SIGTERM)
            request_result.append("sent")

        requester = threading.Thread(target=request_stop, daemon=True)
        requester.start()
        try:
            result = tunnel.serve_foreground(config_file, state_dir)
            requester.join(timeout=5)
            assert request_result == ["sent"]
            assert not _process_is_alive(child.pid)
            if changed_record:
                assert result == (1, "tunnel stopped but changed process state was preserved")
                assert pid_path.read_bytes() == b"replacement-state\n"
            else:
                assert result == (0, None)
                assert not pid_path.exists()
            assert {
                signal.SIGTERM: signal.getsignal(signal.SIGTERM),
                signal.SIGINT: signal.getsignal(signal.SIGINT),
            } == previous_handlers
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_cli_hides_internal_failure_and_closes_owned_pidfd(
        self,
        fake_bin: None,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        import transitvpn.tunnel as tunnel_module
        from transitvpn.cli import main

        monkeypatch.chdir(tmp_path)
        state_path = tmp_path / "state"
        state_path.mkdir()
        (state_path / "xray-server.json").write_text(json.dumps({"server": "fake"}))
        monkeypatch.setattr(tunnel_module, "validate_configs", lambda *_args, **_kwargs: {})
        tracked_fds: list[int] = []
        real_pidfd_open = tunnel_module.os.pidfd_open

        def capture_pidfd(pid: int, flags: int) -> int:
            fd = real_pidfd_open(pid, flags)
            tracked_fds.append(fd)
            return fd

        monkeypatch.setattr(tunnel_module.os, "pidfd_open", capture_pidfd)

        monkeypatch.setattr(
            tunnel_module,
            "_wait_for_foreground_child",
            lambda _pidfd: (_ for _ in ()).throw(RuntimeError("private poll diagnostic")),
        )
        exit_code = main(["serve"])
        captured = capsys.readouterr()

        assert exit_code == 1
        assert captured.out == ""
        assert captured.err == "serve: error: foreground service stopped after an internal error\n"
        assert "private poll diagnostic" not in captured.err
        assert not (state_path / "tunnel.pid").exists()
        assert tracked_fds
        for fd in tracked_fds:
            with pytest.raises(OSError):
                os.fstat(fd)


class TestGetStatus:
    def test_not_running_when_no_pid_file(self, state_dir: str) -> None:
        Path(state_dir).mkdir(parents=True)
        running, pid = get_status(state_dir)
        assert running is False
        assert pid is None

    def test_running_true_after_start(
        self, fake_bin: None, config_file: str, state_dir: str
    ) -> None:
        _start_pid, err = start_tunnel(config_file, state_dir)
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

    def test_real_pinned_xray_owned_lifecycle(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        import uuid

        from transitvpn import xray_certification as certification

        executable, _metadata = certification.verify_binary("xray")
        server_port = certification._ephemeral_port()
        socks_port = certification._ephemeral_port()
        while socks_port == server_port:
            socks_port = certification._ephemeral_port()
        configs = certification._configs(server_port, socks_port, str(uuid.uuid4()))
        certification.validate_configs(configs, binary=executable)

        state_dir = tmp_path / "state"
        state_dir.mkdir()
        server_config = state_dir / "xray-server.json"
        certification._write_config(server_config, configs["server"])
        monkeypatch.setenv("TRANSITVPN_PROXY_BIN", executable)

        pid, error = start_tunnel(str(server_config), str(state_dir))
        try:
            assert error is None, error
            assert pid is not None
            assert get_status(str(state_dir)) == (True, pid)
        finally:
            stop_error = stop_tunnel(str(state_dir))
            assert stop_error is None, stop_error
        assert _wait_until_dead(pid, timeout=2.0)
        assert get_status(str(state_dir)) == (False, None)


# ---------------------------------------------------------------------------
# CLI subcommands via real subprocesses with fake proxy
# ---------------------------------------------------------------------------


class TestCLILifecycle:
    """CLI lifecycle checks using fake processes and one pinned-Xray acceptance.

    Fake-process cases spawn the CLI in short-lived subprocesses. The real Xray
    case runs the managed server through an actual crash and restart.
    """

    def test_up_exits_zero_with_valid_config(self, workdir: Path, proxy_binary: str) -> None:
        result = _run_cli("up", workdir, proxy_binary)
        try:
            assert result.returncode == 0, f"up failed:\n{result.stdout}{result.stderr}"
        finally:
            _run_cli("down", workdir, proxy_binary)

    def test_up_creates_pid_file(self, workdir: Path, proxy_binary: str) -> None:
        _run_cli("up", workdir, proxy_binary)
        try:
            assert (workdir / "state" / "tunnel.pid").exists(), "tunnel.pid not created by up"
        finally:
            _run_cli("down", workdir, proxy_binary)

    def test_up_output_contains_pid(self, workdir: Path, proxy_binary: str) -> None:
        result = _run_cli("up", workdir, proxy_binary)
        try:
            assert "pid=" in result.stdout, f"pid not in up output: {result.stdout!r}"
        finally:
            _run_cli("down", workdir, proxy_binary)

    def test_status_reports_live_process_after_up(
        self, workdir: Path, proxy_binary: str
    ) -> None:
        _run_cli("up", workdir, proxy_binary)
        try:
            result = _run_cli("status", workdir, proxy_binary)
            assert "status: live process (pid=" in result.stdout
            assert "tunnel health unverified" in result.stdout
            assert "not running" not in result.stdout
        finally:
            _run_cli("down", workdir, proxy_binary)

    def test_status_reports_crashed_daemon_and_up_recovers(
        self, workdir: Path, proxy_binary: str
    ) -> None:
        pid_file = workdir / "state" / "tunnel.pid"
        pid_file.parent.mkdir(parents=True, exist_ok=True)
        started = _run_cli("up", workdir, proxy_binary)
        assert started.returncode == 0, started.stdout + started.stderr
        record = json.loads(pid_file.read_text(encoding="utf-8"))
        _signal_test_spawned_process(record["pid"], signal.SIGKILL)

        crashed_status = _run_cli("status", workdir, proxy_binary)
        assert crashed_status.returncode == 0
        assert "status: not running; tunnel health unavailable" in crashed_status.stdout
        assert "live process" not in crashed_status.stdout

        recovered_up = _run_cli("up", workdir, proxy_binary)
        try:
            assert recovered_up.returncode == 0, (
                f"up did not recover after a crashed daemon:\n"
                f"{recovered_up.stdout}{recovered_up.stderr}"
            )
            recovered_status = _run_cli("status", workdir, proxy_binary)
            assert recovered_status.returncode == 0
            assert "status: live process (pid=" in recovered_status.stdout
            assert "tunnel health unverified" in recovered_status.stdout
        finally:
            _run_cli("down", workdir, proxy_binary)

    def test_real_xray_crash_restart_proves_http_and_status_stays_cautious(self) -> None:
        """Exercise the managed daemon restart against real pinned Xray traffic."""
        import socket
        import tempfile
        import threading
        import uuid

        from transitvpn import xray_certification as certification
        from transitvpn.tunnel import get_status

        executable, _ = certification.verify_binary("xray")
        response_body = ("restart-proof:" + uuid.uuid4().hex).encode("ascii")
        responder = certification._Responder(response_body)
        responder_thread = threading.Thread(
            target=responder.serve_forever, daemon=True
        )
        client_process = None
        responder_started = False

        with tempfile.TemporaryDirectory(
            prefix="transitvpn-restart-acceptance-"
        ) as raw_dir:
            workdir = Path(raw_dir)
            state_dir = workdir / "state"
            state_dir.mkdir()

            server_port = certification._ephemeral_port()
            socks_port = certification._ephemeral_port()
            while socks_port == server_port:
                socks_port = certification._ephemeral_port()

            configs = certification._configs(
                server_port,
                socks_port,
                str(uuid.uuid4()),
                responder_port=int(responder.server_address[1]),
            )
            certification.validate_configs(configs, binary=executable)
            server_config = state_dir / "xray-server.json"
            client_config = workdir / "xray-client.json"
            certification._write_config(server_config, configs["server"])
            certification._write_config(client_config, configs["client"])

            project_root = Path(__file__).resolve().parents[1]
            env = {
                **os.environ,
                "PYTHONPATH": str(project_root)
                + os.pathsep
                + os.environ.get("PYTHONPATH", ""),
                "TRANSITVPN_PROXY_BIN": executable,
            }
            entrypoint = (
                "import sys; from transitvpn.cli import main; "
                "raise SystemExit(main(sys.argv[1:]))"
            )

            def run_cli(command: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, "-c", entrypoint, command],
                    capture_output=True,
                    text=True,
                    cwd=str(workdir),
                    env=env,
                    timeout=20,
                    check=False,
                )

            def wait_server_ready(timeout: float = 10.0) -> None:
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    running, _ = get_status(str(state_dir))
                    if not running:
                        raise AssertionError("managed Xray daemon exited before becoming ready")
                    try:
                        with socket.create_connection(
                            ("127.0.0.1", server_port), timeout=0.1
                        ):
                            return
                    except OSError:
                        time.sleep(0.025)
                raise AssertionError("managed Xray server did not become ready")

            try:
                responder_thread.start()
                responder_started = True

                first_up = run_cli("up")
                assert first_up.returncode == 0, first_up.stdout + first_up.stderr
                server_pid_file = state_dir / "tunnel.pid"
                first_pid = json.loads(server_pid_file.read_text(encoding="utf-8"))["pid"]
                wait_server_ready()

                client_process = certification._start(
                    executable, client_config, "client"
                )
                certification._wait_ready(
                    client_process, socks_port, "client", time.monotonic() + 10.0
                )
                status_before = run_cli("status")
                assert status_before.returncode == 0
                assert "status: live process (pid=" in status_before.stdout
                assert "tunnel health unverified" in status_before.stdout
                assert certification._probe(
                    socks_port,
                    int(responder.server_address[1]),
                    response_body,
                    timeout=5.0,
                ) == len(response_body)
                assert responder.request_count == 1

                _signal_test_spawned_process(first_pid, signal.SIGKILL)
                crash_deadline = time.monotonic() + 5.0
                while (
                    get_status(str(state_dir))[0]
                    and time.monotonic() < crash_deadline
                ):
                    time.sleep(0.025)
                assert not get_status(str(state_dir))[0], "killed daemon still appears live"
                crashed_status = run_cli("status")
                assert crashed_status.returncode == 0
                assert (
                    "status: not running; tunnel health unavailable"
                    in crashed_status.stdout
                )
                assert client_process.poll() is None, "negative control lost the client process"
                with pytest.raises(certification.XrayCertificationError):
                    certification._probe(
                        socks_port,
                        int(responder.server_address[1]),
                        response_body,
                        timeout=2.0,
                    )
                assert responder.request_count == 1

                restarted = run_cli("up")
                assert restarted.returncode == 0, restarted.stdout + restarted.stderr
                wait_server_ready()
                status_after = run_cli("status")
                assert status_after.returncode == 0
                assert "status: live process (pid=" in status_after.stdout
                assert "tunnel health unverified" in status_after.stdout
                assert certification._probe(
                    socks_port,
                    int(responder.server_address[1]),
                    response_body,
                    timeout=5.0,
                ) == len(response_body)
                assert responder.request_count == 2

                # A live server PID is not proof that a client data path works.
                assert certification._stop(client_process)
                client_process = None
                with pytest.raises(certification.XrayCertificationError):
                    certification._probe(
                        socks_port,
                        int(responder.server_address[1]),
                        response_body,
                        timeout=2.0,
                    )
                process_only_status = run_cli("status")
                assert process_only_status.returncode == 0
                assert "status: live process (pid=" in process_only_status.stdout
                assert "tunnel health unverified" in process_only_status.stdout
                assert "working tunnel" not in process_only_status.stdout
                assert responder.request_count == 2
            finally:
                if client_process is not None:
                    assert certification._stop(client_process)
                down = run_cli("down")
                assert down.returncode == 0, down.stdout + down.stderr
                if responder_started:
                    assert certification._stop_responder(responder, responder_thread)
                else:
                    responder.server_close()

    def test_down_kills_process_and_removes_pid(self, workdir: Path, proxy_binary: str) -> None:
        _run_cli("up", workdir, proxy_binary)
        pid_file = workdir / "state" / "tunnel.pid"
        pid = json.loads(pid_file.read_text())["pid"]
        _run_cli("down", workdir, proxy_binary)
        assert not pid_file.exists(), "tunnel.pid still present after down"
        assert _wait_until_dead(pid), f"process {pid} still alive after down"

    def test_down_reports_refusal_for_untrusted_state(self, workdir: Path, proxy_binary: str) -> None:
        pid_file = workdir / "state" / "tunnel.pid"
        pid_file.write_text("not-a-process-identity\n")
        result = _run_cli("down", workdir, proxy_binary)
        assert result.returncode == 1
        assert "down: error:" in result.stdout
        assert "tunnel stopped" not in result.stdout
        assert pid_file.read_text() == "not-a-process-identity\n"

    def test_status_returns_not_running_after_down(self, workdir: Path, proxy_binary: str) -> None:
        _run_cli("up", workdir, proxy_binary)
        _run_cli("down", workdir, proxy_binary)
        result = _run_cli("status", workdir, proxy_binary)
        assert "not running" in result.stdout

    def test_double_down_exits_zero_both_times(self, workdir: Path, proxy_binary: str) -> None:
        _run_cli("up", workdir, proxy_binary)
        r1 = _run_cli("down", workdir, proxy_binary)
        r2 = _run_cli("down", workdir, proxy_binary)
        assert r1.returncode == 0
        assert r2.returncode == 0

    def test_double_down_both_print_down_prefix(self, workdir: Path, proxy_binary: str) -> None:
        _run_cli("up", workdir, proxy_binary)
        r1 = _run_cli("down", workdir, proxy_binary)
        r2 = _run_cli("down", workdir, proxy_binary)
        assert "down:" in r1.stdout
        assert "down:" in r2.stdout

    def test_down_exits_zero_when_no_tunnel_running(self, workdir: Path, proxy_binary: str) -> None:
        result = _run_cli("down", workdir, proxy_binary)
        assert result.returncode == 0
