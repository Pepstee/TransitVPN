from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from transitvpn.xray import validate_configs, verify_binary

# The marker is inherited by the verified child and checked with its live
# kernel process identity. Only its digest is stored in tunnel.pid.
_OWNER_ENV = "TRANSITVPN_TUNNEL_OWNER"
_STATE_SCHEMA = "transitvpn.process-identity.v1"
_STATE_FIELDS = {
    "schema",
    "pid",
    "boot_id",
    "start_time_ticks",
    "config_path",
    "verified_executable",
    "process_executable",
    "cmdline_sha256",
    "owner_token_sha256",
}
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Seconds to let the proxy settle before confirming it is still alive. A bad
# config or an already-bound port makes xray exit within milliseconds, so a
# brief liveness check turns "I spawned a process" into "the tunnel is up".
_STARTUP_SETTLE_SECONDS = 0.25
_STOP_GRACE_SECONDS = 5.0
_DEFAULT_PID_NAME = "tunnel.pid"


def _pid_file_path(state_dir: Path, pid_name: str) -> Path:
    """Resolve one plain process-record filename inside the state directory."""
    if (
        not isinstance(pid_name, str)
        or not pid_name
        or Path(pid_name).name != pid_name
        or pid_name in {".", ".."}
    ):
        raise ValueError("invalid process record name")
    return state_dir / pid_name


def lifecycle_support_error() -> str | None:
    """Return a truthful limit when this OS cannot bind signals to one PID instance."""
    if (
        not sys.platform.startswith("linux")
        or not callable(getattr(os, "pidfd_open", None))
        or not callable(getattr(signal, "pidfd_send_signal", None))
    ):
        return (
            "safe tunnel process ownership requires Linux pidfd support; "
            "refusing to manage a process on this platform"
        )
    return None


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _read_proc_start(pid: int) -> tuple[str, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        # comm is parenthesized but may itself contain spaces or ')'.
        tail = raw.rsplit(")", 1)[1].split()
        if len(tail) <= 19 or tail[0] in {"Z", "X"}:
            return None
        return tail[0], int(tail[19])
    except (OSError, IndexError, ValueError):
        return None


def _read_live_identity(pid: int, pidfd: int) -> tuple[dict[str, object], list[str]] | None:
    """Snapshot one process while pidfd pins its incarnation; never signal here."""
    if _pidfd_exited(pidfd):
        return None
    before = _read_proc_start(pid)
    if before is None:
        return None
    try:
        process_executable = str(Path(os.readlink(f"/proc/{pid}/exe")).resolve(strict=True))
        raw_cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        raw_environment = Path(f"/proc/{pid}/environ").read_bytes()
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except (OSError, RuntimeError):
        return None
    after = _read_proc_start(pid)
    # Scheduling state may legitimately move R<->S between these reads.
    # Start ticks identify the same incarnation; _read_proc_start rejects Z/X
    # in both snapshots, and pidfd checks independently reject an exit race.
    if after is None or before[1] != after[1] or _pidfd_exited(pidfd):
        return None

    marker_prefix = os.fsencode(_OWNER_ENV) + b"="
    owner_values = [
        entry[len(marker_prefix):]
        for entry in raw_environment.split(b"\0")
        if entry.startswith(marker_prefix)
    ]
    if len(owner_values) != 1 or not owner_values[0]:
        return None
    argv = [os.fsdecode(arg) for arg in raw_cmdline.split(b"\0") if arg]
    if not argv:
        return None

    identity: dict[str, object] = {
        "boot_id": boot_id,
        "start_time_ticks": before[1],
        "process_executable": process_executable,
        "cmdline_sha256": hashlib.sha256(raw_cmdline).hexdigest(),
        "owner_token_sha256": hashlib.sha256(owner_values[0]).hexdigest(),
    }
    return identity, argv


def _invocation_matches(
    verified_executable: str,
    config_path: str,
    process_executable: str,
    argv: list[str],
) -> bool:
    """Match the exact Popen argv, including only its kernel shebang rewrite."""
    try:
        expected = str(Path(verified_executable).resolve(strict=True))
    except OSError:
        return False
    requested = [expected, "run", "-config", config_path]
    if process_executable == expected:
        return argv == requested

    # Linux rewrites argv for an executable script to exactly:
    # [shebang interpreter, optional shebang argument, script, requested args...].
    # Validate that full transformation rather than accepting the verified path
    # merely because it appears somewhere in an arbitrary process argv.
    try:
        with open(expected, "rb") as handle:
            first_line = handle.readline(4096)
        if not first_line.startswith(b"#!"):
            return False
        shebang = os.fsdecode(first_line[2:].strip()).split(None, 1)
        if not shebang:
            return False
        interpreter = shebang[0]
        expected_process_exe = str(Path(interpreter).resolve(strict=True))
        expected_argv = [interpreter]
        if len(shebang) == 2:
            expected_argv.append(shebang[1])
        expected_argv.extend([expected, "run", "-config", config_path])
    except OSError:
        return False
    return process_executable == expected_process_exe and argv == expected_argv


def _read_record(pid_file: Path) -> tuple[dict[str, object] | None, bytes | None]:
    """Strictly load only the current structured format; legacy PID files are untrusted."""
    try:
        mode = pid_file.lstat().st_mode
        if not stat.S_ISREG(mode):
            return None, b""
        raw = pid_file.read_bytes()
    except FileNotFoundError:
        return None, None
    except OSError:
        return None, b""
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, raw
    if not isinstance(value, dict) or set(value) != _STATE_FIELDS:
        return None, raw
    if value.get("schema") != _STATE_SCHEMA:
        return None, raw
    if type(value.get("pid")) is not int or value["pid"] <= 0:
        return None, raw
    if type(value.get("start_time_ticks")) is not int or value["start_time_ticks"] <= 0:
        return None, raw
    for name in ("boot_id", "config_path", "verified_executable", "process_executable"):
        if not isinstance(value.get(name), str) or not value[name]:
            return None, raw
    for name in ("config_path", "verified_executable", "process_executable"):
        if not Path(value[name]).is_absolute():
            return None, raw
    for name in ("cmdline_sha256", "owner_token_sha256"):
        if not isinstance(value.get(name), str) or not _HASH_RE.fullmatch(value[name]):
            return None, raw
    return value, raw


def _identity_matches(record: dict[str, object], pidfd: int) -> bool:
    try:
        result = _read_live_identity(record["pid"], pidfd)
    except (TypeError, ValueError):
        return False
    if result is None:
        return False
    current, argv = result
    if not _invocation_matches(
        record["verified_executable"],
        record["config_path"],
        current["process_executable"],
        argv,
    ):
        return False
    for name in (
        "boot_id",
        "start_time_ticks",
        "process_executable",
        "cmdline_sha256",
        "owner_token_sha256",
    ):
        if current[name] != record[name]:
            return False
    return not _pidfd_exited(pidfd)


def _write_record_atomic(
    pid_file: Path,
    record: dict[str, object],
    expected_previous: bytes | None,
) -> None:
    payload = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=".tunnel.pid.", dir=pid_file.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            current = pid_file.read_bytes()
        except FileNotFoundError:
            current = None
        if current != expected_previous:
            raise OSError("tunnel state changed during start; preserving the current record")
        os.replace(temporary, pid_file)
        directory_fd = os.open(pid_file.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _remove_record_if_unchanged(pid_file: Path, original: bytes) -> bool:
    try:
        if pid_file.read_bytes() != original:
            return False
        pid_file.unlink()
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _signal_pidfd(pidfd: int, sig: int) -> None:
    # Python's platform API sends through the already-open incarnation handle.
    signal.pidfd_send_signal(pidfd, sig)


def _wait_pidfd_exit(pidfd: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while not _pidfd_exited(pidfd) and time.monotonic() < deadline:
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    return _pidfd_exited(pidfd)


def _cleanup_spawned_pidfd(pidfd: int) -> bool:
    """Clean up a failed start through the pidfd opened for its own child."""
    if _pidfd_exited(pidfd):
        return True
    try:
        _signal_pidfd(pidfd, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    if _wait_pidfd_exit(pidfd, 1.0):
        return True
    try:
        _signal_pidfd(pidfd, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return _wait_pidfd_exit(pidfd, 1.0)


def _startup_failure(pidfd: int, reason: str) -> tuple[None, str]:
    if _cleanup_spawned_pidfd(pidfd):
        return None, f"{reason}; spawned process stopped safely"
    return None, f"{reason}; spawned process may remain alive, and state was not recorded"


def start_tunnel(
    config_path: str,
    state_dir: str,
    *,
    pid_name: str = _DEFAULT_PID_NAME,
) -> tuple[int | None, str | None]:
    config = Path(config_path)
    if not config.exists():
        return None, f"config not found: {config_path}"

    try:
        json.loads(config.read_text())
    except json.JSONDecodeError as e:
        return None, f"invalid config JSON: {e}"

    support_error = lifecycle_support_error()
    if support_error:
        return None, support_error

    binary = os.environ.get("TRANSITVPN_PROXY_BIN", "xray")
    try:
        executable, _ = verify_binary(binary)
    except RuntimeError as exc:
        return None, str(exc)
    executable = str(Path(executable).resolve())
    config_path = str(config.resolve())
    cmd = [executable, "run", "-config", config_path]

    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)
    try:
        pid_file = _pid_file_path(state, pid_name)
    except ValueError:
        return None, "invalid process record name"
    existing, existing_raw = _read_record(pid_file)
    if existing_raw is not None:
        if existing is None:
            return None, "existing tunnel state is unverifiable; refusing to start; state preserved"
        try:
            existing_pidfd = os.pidfd_open(existing["pid"], 0)
        except ProcessLookupError:
            # The recorded owner is gone. Replacing this stale, structured record
            # cannot signal a reused PID; the new child receives a fresh marker.
            pass
        except OSError:
            return None, "existing tunnel process cannot be verified safely; refusing to start"
        else:
            try:
                if _pidfd_exited(existing_pidfd):
                    # A zombie may still be visible to pidfd_open until its
                    # parent reaps it. It is already exited and cannot be
                    # signaled; allow recovery from that stale owned record.
                    pass
                elif _identity_matches(existing, existing_pidfd):
                    return None, f"tunnel already running (pid={existing['pid']})"
                else:
                    return None, "existing tunnel identity does not match; refusing to start; state preserved"
            finally:
                os.close(existing_pidfd)

    owner_token = secrets.token_hex(32)
    child_environment = os.environ.copy()
    child_environment[_OWNER_ENV] = owner_token
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=child_environment,
        )
    except FileNotFoundError:
        return None, f"binary not found: {cmd[0]}"
    except OSError as e:
        return None, str(e)

    try:
        # Acquire the kernel incarnation handle before inspecting identity.
        pidfd = os.pidfd_open(proc.pid, 0)
    except OSError:
        exit_code = proc.poll()
        if exit_code is not None:
            return None, (
                f"proxy exited immediately (code {exit_code}) before a safe process handle "
                "was acquired"
            )
        return None, (
            f"started process (pid={proc.pid}) remains alive but untracked because "
            "pidfd_open failed; no signal was sent and no state was recorded"
        )

    try:
        time.sleep(_STARTUP_SETTLE_SECONDS)
        exit_code = proc.poll()
        if exit_code is not None:
            return None, (
                f"proxy exited immediately (code {exit_code}) — "
                "check the config and that the port is free"
            )

        observed = _read_live_identity(proc.pid, pidfd)
        if observed is None:
            return _startup_failure(
                pidfd, "started process identity could not be verified; state was not recorded"
            )
        identity, argv = observed
        if not _invocation_matches(executable, config_path, identity["process_executable"], argv):
            return _startup_failure(
                pidfd,
                "started process did not match the verified invocation; state was not recorded",
            )
        if not hmac.compare_digest(
            identity["owner_token_sha256"], hashlib.sha256(owner_token.encode("ascii")).hexdigest()
        ):
            return _startup_failure(
                pidfd, "started process ownership marker did not match; state was not recorded"
            )

        record: dict[str, object] = {
            "schema": _STATE_SCHEMA,
            "pid": proc.pid,
            "config_path": config_path,
            "verified_executable": executable,
            **identity,
        }
        try:
            _write_record_atomic(pid_file, record, existing_raw)
        except OSError:
            return _startup_failure(
                pidfd,
                "started process identity was verified but its state record could not be saved",
            )
        return proc.pid, None
    finally:
        os.close(pidfd)


def stop_tunnel(
    state_dir: str, *, pid_name: str = _DEFAULT_PID_NAME
) -> str | None:
    """Stop only the exact process incarnation recorded by start_tunnel.

    An error is returned for ambiguous state, and that state is preserved. The
    caller must not report a successful stop when this returns a message.
    """
    try:
        pid_file = _pid_file_path(Path(state_dir), pid_name)
    except ValueError:
        return "invalid process record name"
    record, original = _read_record(pid_file)
    if original is None:
        return None
    if record is None:
        return "unverifiable tunnel state; refusing to signal; state preserved"
    support_error = lifecycle_support_error()
    if support_error:
        return support_error

    try:
        pidfd = os.pidfd_open(record["pid"], 0)
    except ProcessLookupError:
        if not _remove_record_if_unchanged(pid_file, original):
            return "stale tunnel state changed concurrently; refusing to remove it"
        return None
    except OSError:
        return "tunnel process cannot be verified safely; state preserved"

    try:
        if not _identity_matches(record, pidfd):
            return "tunnel process identity does not match; refusing to signal; state preserved"
        try:
            _signal_pidfd(pidfd, signal.SIGTERM)
        except ProcessLookupError:
            if not _remove_record_if_unchanged(pid_file, original):
                return "stale tunnel state changed concurrently; refusing to remove it"
            return None
        except OSError:
            return "could not signal the verified tunnel process; state preserved"

        if not _wait_pidfd_exit(pidfd, _STOP_GRACE_SECONDS):
            # Recheck the exact invocation before escalating. If it exec'd into
            # another image, do not force-kill it even though the PID is stable.
            if not _identity_matches(record, pidfd):
                return "tunnel identity changed during shutdown; refusing to force-stop; state preserved"
            try:
                _signal_pidfd(pidfd, signal.SIGKILL)
            except ProcessLookupError:
                if not _remove_record_if_unchanged(pid_file, original):
                    return "stale tunnel state changed concurrently; refusing to remove it"
                return None
            except OSError:
                return "could not force-stop the verified tunnel process; state preserved"
            if not _wait_pidfd_exit(pidfd, 1.0):
                return "verified tunnel process did not exit; state preserved"

        if not _remove_record_if_unchanged(pid_file, original):
            return "tunnel stopped, but its state record changed and was preserved"
        return None
    finally:
        os.close(pidfd)


def get_status(
    state_dir: str, *, pid_name: str = _DEFAULT_PID_NAME
) -> tuple[bool, int | None]:
    if lifecycle_support_error():
        return False, None
    try:
        pid_file = _pid_file_path(Path(state_dir), pid_name)
    except ValueError:
        return False, None
    record, raw = _read_record(pid_file)
    if raw is None or record is None:
        return False, None
    try:
        pidfd = os.pidfd_open(record["pid"], 0)
    except OSError:
        return False, None
    try:
        if _identity_matches(record, pidfd):
            return True, record["pid"]
        return False, None
    finally:
        os.close(pidfd)


def _reap_direct_child(pid: int, timeout: float = 1.0) -> bool:
    """Reap the child created by start_tunnel without an unbounded wait."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            waited, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True
        except OSError:
            return False
        if waited == pid:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.025)


def _stop_foreground_child(record: dict[str, object], pidfd: int) -> bool:
    """Stop only the foreground command's verified child through its pidfd."""
    if _pidfd_exited(pidfd):
        return True
    if not _identity_matches(record, pidfd):
        return False
    try:
        _signal_pidfd(pidfd, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False

    if not _wait_pidfd_exit(pidfd, _STOP_GRACE_SECONDS):
        if not _identity_matches(record, pidfd):
            return False
        try:
            _signal_pidfd(pidfd, signal.SIGKILL)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        if not _wait_pidfd_exit(pidfd, 1.0):
            return False
    return True


def _wait_for_foreground_child(pidfd: int) -> None:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        poller.poll(250)
    except InterruptedError:
        pass


def serve_foreground(
    config_path: str,
    state_dir: str,
    *,
    config_name: str = "server",
    pid_name: str = _DEFAULT_PID_NAME,
) -> tuple[int, str | None]:
    """Run one verified Xray child until it exits or this foreground owner is stopped.

    A service manager may restart the command after an unexpected child exit. This
    function deliberately has no restart loop of its own.
    """
    support_error = lifecycle_support_error()
    if support_error:
        return 1, "safe foreground service is unavailable on this platform"
    if config_name not in {"server", "client"}:
        return 1, "invalid foreground tunnel role"

    config = Path(config_path)
    try:
        config_value = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return 1, "tunnel configuration could not be read"
    if not isinstance(config_value, dict):
        return 1, "tunnel configuration is invalid"

    binary = os.environ.get("TRANSITVPN_PROXY_BIN", "xray")
    try:
        validate_configs({config_name: config_value}, binary=binary)
    except (RuntimeError, ValueError, OSError, TypeError):
        return 1, "tunnel configuration failed pinned Xray validation"

    try:
        pid, start_error = start_tunnel(
            str(config), state_dir, pid_name=pid_name
        )
    except Exception:  # noqa: BLE001 - keep internal startup details out of service output
        return 1, "verified tunnel process could not be started"
    if start_error is not None or pid is None:
        return 1, "verified tunnel process could not be started"

    try:
        pid_file = _pid_file_path(Path(state_dir), pid_name)
    except ValueError:
        return 1, "foreground process state is invalid"
    record, original = _read_record(pid_file)
    if record is None or original is None or record["pid"] != pid:
        return 1, "foreground process ownership could not be verified"
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError:
        return 1, "foreground process handle could not be opened safely"

    owned = False
    handlers: dict[int, object] = {}
    stop_requested = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True

    try:
        if not _identity_matches(record, pidfd):
            return 1, "foreground process identity could not be verified"
        owned = True
        handlers = {
            signal.SIGTERM: signal.getsignal(signal.SIGTERM),
            signal.SIGINT: signal.getsignal(signal.SIGINT),
        }
        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)

        while not stop_requested:
            if _pidfd_exited(pidfd):
                reaped = _reap_direct_child(pid)
                removed = _remove_record_if_unchanged(pid_file, original)
                if not reaped:
                    return 1, "unexpected tunnel exit could not be reaped"
                if not removed:
                    return 1, "unexpected tunnel exit left changed process state"
                return 1, "managed tunnel exited unexpectedly"
            _wait_for_foreground_child(pidfd)

        if not _stop_foreground_child(record, pidfd):
            return 1, "verified tunnel process could not be stopped safely"
        if not _reap_direct_child(pid):
            return 1, "stopped tunnel process could not be reaped"
        if not _remove_record_if_unchanged(pid_file, original):
            return 1, "tunnel stopped but changed process state was preserved"
        return 0, None
    except Exception:  # noqa: BLE001 - suppress diagnostics after safe child cleanup
        if owned and _stop_foreground_child(record, pidfd):
            _reap_direct_child(pid)
            _remove_record_if_unchanged(pid_file, original)
        return 1, "foreground service stopped after an internal error"
    finally:
        for signum, previous in handlers.items():
            signal.signal(signum, previous)
        os.close(pidfd)
