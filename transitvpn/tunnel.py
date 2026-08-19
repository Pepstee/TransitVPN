import json
import os
import signal
import subprocess
import time
from pathlib import Path

# Seconds to let the proxy settle before confirming it is still alive. A bad
# config or an already-bound port makes xray exit within milliseconds, so a
# brief liveness check turns "I spawned a process" into "the tunnel is up".
_STARTUP_SETTLE_SECONDS = 0.25


def start_tunnel(config_path: str, state_dir: str) -> tuple[int | None, str | None]:
    config = Path(config_path)
    if not config.exists():
        return None, f"config not found: {config_path}"

    try:
        json.loads(config.read_text())
    except json.JSONDecodeError as e:
        return None, f"invalid config JSON: {e}"

    binary = os.environ.get("TRANSITVPN_PROXY_BIN", "xray")
    # TRANSITVPN_PROXY_BIN may be "python -c ..." so split it
    if " " in binary:
        cmd = binary.split(None, 2) + ["-config", config_path]
    else:
        cmd = [binary, "-config", config_path]

    state = Path(state_dir)
    state.mkdir(parents=True, exist_ok=True)

    pid_file = state / "tunnel.pid"
    if pid_file.exists():
        try:
            existing_pid = int(pid_file.read_text().strip())
            os.kill(existing_pid, 0)
            return None, f"tunnel already running (pid={existing_pid})"
        except (ValueError, OSError, ProcessLookupError):
            pass

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return None, f"binary not found: {cmd[0]}"
    except OSError as e:
        return None, str(e)

    # Confirm the proxy actually stayed up. Reporting "started" for a process
    # that already died (bad config, port in use) would be an unverified
    # success — the tunnel must be demonstrated, not assumed.
    time.sleep(_STARTUP_SETTLE_SECONDS)
    exit_code = proc.poll()
    if exit_code is not None:
        return None, (
            f"proxy exited immediately (code {exit_code}) — "
            "check the config and that the port is free"
        )

    pid_file.write_text(str(proc.pid))
    return proc.pid, None


def stop_tunnel(state_dir: str) -> None:
    pid_file = Path(state_dir) / "tunnel.pid"
    if not pid_file.exists():
        return

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        pid_file.unlink(missing_ok=True)
        return

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pid_file.unlink(missing_ok=True)
        return
    except PermissionError:
        pid_file.unlink(missing_ok=True)
        return

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    pid_file.unlink(missing_ok=True)


def get_status(state_dir: str) -> tuple[bool, int | None]:
    pid_file = Path(state_dir) / "tunnel.pid"
    if not pid_file.exists():
        return False, None

    try:
        pid = int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return False, None

    try:
        os.kill(pid, 0)
        return True, pid
    except ProcessLookupError:
        return False, None
    except PermissionError:
        # process exists but owned by another user
        return True, pid
