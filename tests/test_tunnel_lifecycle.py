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

def _write_test_binary(path: Path, body: str = "exec sleep 30") -> str:
    # Temporary executable has a distinct lifecycle: it exists only for this test.
    path.write_text("#!/bin/sh\n" + body + "\n")
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
        executable = _write_test_binary(tmp_path / "exiting-proxy", "exit 3")
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
        pid_file.write_text(str(_dead_pid()), encoding="utf-8")

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
                first_pid = int(server_pid_file.read_text(encoding="utf-8"))
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

                os.kill(first_pid, signal.SIGKILL)
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
        pid = int(pid_file.read_text().strip())
        _run_cli("down", workdir, proxy_binary)
        assert not pid_file.exists(), "tunnel.pid still present after down"
        assert _wait_until_dead(pid), f"process {pid} still alive after down"

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
