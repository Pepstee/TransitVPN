"""Local, self-cleaning certification of an Xray server/client data path."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid
from typing import Any

from transitvpn.xray import XRAY_VERSION, validate_configs, verify_binary


_LOOPBACK = "127.0.0.1"


class XrayCertificationError(RuntimeError):
    """A closed failure of the local Xray tunnel certification."""


@dataclass(frozen=True)
class XrayTunnelCertification:
    """Non-sensitive evidence returned by a successful certification."""

    version: str
    response_bytes: int

    def operator_record(self) -> dict[str, object]:
        """Render credential-free evidence without overstating its scope."""
        return {
            "version": self.version,
            "response_bytes": self.response_bytes,
            "local_evidence": {
                "scope": "loopback",
                "proxy": "observed",
                "routing": "observed",
                "dns": "observed",
                "cleanup": "observed",
            },
            "external_recovery": {"status": "unprovisioned", "observed": False},
        }


class _Responder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, body: bytes) -> None:
        self.response_body = body
        super().__init__((_LOOPBACK, 0), _RequestHandler)


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = self.server.response_body  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Request logs are neither useful evidence nor safe repository artefacts.
        return


def _ephemeral_port() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((_LOOPBACK, 0))
            return int(listener.getsockname()[1])
    except OSError as exc:
        raise XrayCertificationError("could not allocate a loopback port") from exc


def _configs(server_port: int, socks_port: int, client_id: str) -> dict[str, dict[str, Any]]:
    common_log = {"loglevel": "none"}
    server = {
        "log": common_log,
        "inbounds": [{
            "listen": _LOOPBACK,
            "port": server_port,
            "protocol": "vless",
            "settings": {
                "clients": [{"id": client_id}],
                "decryption": "none",
            },
            "streamSettings": {"network": "raw", "security": "none"},
        }],
        "outbounds": [{"protocol": "freedom"}],
    }
    client = {
        "log": common_log,
        "inbounds": [{
            "listen": _LOOPBACK,
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": _LOOPBACK,
                "port": server_port,
                "users": [{"id": client_id, "encryption": "none"}],
            }]},
            "streamSettings": {"network": "raw", "security": "none"},
        }],
    }
    return {"server": server, "client": client}


def _write_config(path: Path, config: dict[str, Any]) -> None:
    try:
        path.write_text(json.dumps(config, separators=(",", ":")), encoding="utf-8")
        path.chmod(0o600)
    except (OSError, TypeError, ValueError) as exc:
        raise XrayCertificationError("generated Xray configuration could not be written") from exc


def _start(executable: str, config: Path, role: str) -> subprocess.Popen[bytes]:
    try:
        return subprocess.Popen(
            [executable, "run", "-config", str(config)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except OSError as exc:
        raise XrayCertificationError(f"{role} Xray process could not be started") from exc


def _wait_ready(process: subprocess.Popen[bytes], port: int, role: str, deadline: float) -> None:
    while time.monotonic() < deadline:
        return_code = process.poll()
        if return_code is not None:
            raise XrayCertificationError(
                f"{role} Xray process exited during startup (code {return_code})"
            )
        try:
            with socket.create_connection((_LOOPBACK, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.025)
    raise XrayCertificationError(f"{role} Xray readiness check timed out")


def _set_remaining_timeout(connection: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise XrayCertificationError("application-data tunnel probe timed out")
    connection.settimeout(remaining)


def _receive_exact(connection: socket.socket, count: int, deadline: float | None = None) -> bytes:
    data = bytearray()
    while len(data) < count:
        if deadline is not None:
            _set_remaining_timeout(connection, deadline)
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise XrayCertificationError("SOCKS endpoint closed an incomplete response")
        data.extend(chunk)
    return bytes(data)


def _probe(socks_port: int, upstream_port: int, expected_body: bytes, timeout: float) -> int:
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((_LOOPBACK, socks_port), timeout=timeout) as connection:
            _set_remaining_timeout(connection, deadline)
            connection.sendall(b"\x05\x01\x00")
            if _receive_exact(connection, 2, deadline) != b"\x05\x00":
                raise XrayCertificationError("client SOCKS endpoint rejected no-auth negotiation")

            # Domain-form SOCKS establishes proxy-side DNS handling as well as
            # routing; an IP-form request cannot support a DNS assertion.
            hostname = b"localhost"
            request = b"\x05\x01\x00\x03" + bytes((len(hostname),)) + hostname
            request += upstream_port.to_bytes(2, "big")
            connection.sendall(request)
            reply = _receive_exact(connection, 4, deadline)
            if reply[0] != 5 or reply[1] != 0:
                raise XrayCertificationError("client SOCKS endpoint could not reach the responder")
            address_size = {1: 4, 4: 16}.get(reply[3])
            if reply[3] == 3:
                address_size = _receive_exact(connection, 1, deadline)[0]
            if address_size is None:
                raise XrayCertificationError("client SOCKS endpoint returned an invalid address")
            _receive_exact(connection, address_size + 2, deadline)

            _set_remaining_timeout(connection, deadline)
            connection.sendall(b"GET /certify HTTP/1.0\r\nHost: local\r\n\r\n")
            response = bytearray()
            while True:
                _set_remaining_timeout(connection, deadline)
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
    except XrayCertificationError:
        raise
    except Exception as exc:
        raise XrayCertificationError("application-data tunnel probe failed") from exc

    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator or not header.startswith(b"HTTP/1.0 200 ") or body != expected_body:
        raise XrayCertificationError("application-data tunnel probe returned an invalid response")
    return len(body)


def _stop(process: subprocess.Popen[bytes] | None) -> bool:
    """Stop one child and report whether its exit was observed."""
    if process is None:
        return True
    try:
        if process.poll() is not None:
            return True
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
        return process.poll() is not None
    except Exception:
        return False


def _stop_all(*processes: subprocess.Popen[bytes] | None) -> None:
    """Attempt every child cleanup and fail closed unless all exits are observed."""
    stopped = True
    for process in processes:
        try:
            stopped = _stop(process) and stopped
        except Exception:
            stopped = False
    if not stopped:
        raise XrayCertificationError("Xray process cleanup could not be confirmed")


def _stop_responder(responder: socketserver.TCPServer, thread: threading.Thread) -> bool:
    stopped = True
    for operation in (responder.shutdown, responder.server_close):
        try:
            operation()
        except Exception:
            stopped = False
    try:
        thread.join(timeout=2)
        if thread.is_alive():
            stopped = False
    except Exception:
        stopped = False
    return stopped


def certify_local_tunnel(
    xray_binary: str = "xray", *, timeout: float = 10.0
) -> XrayTunnelCertification:
    """Prove HTTP bytes traverse a local SOCKS -> Xray -> HTTP path.

    The binary is pinned and both configurations are validated before launch.
    All credentials and configuration files live in an automatically removed
    system temporary directory; child output is never written to disk.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    try:
        executable, _ = verify_binary(xray_binary)
    except RuntimeError as exc:
        raise XrayCertificationError(f"Xray binary verification failed: {exc}") from exc

    server_process: subprocess.Popen[bytes] | None = None
    client_process: subprocess.Popen[bytes] | None = None
    response_body = ("transitvpn-xray-certification:" + secrets.token_hex(16)).encode("ascii")
    try:
        responder = _Responder(response_body)
    except OSError as exc:
        raise XrayCertificationError("local HTTP responder could not be started") from exc
    responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
    try:
        responder_thread.start()
    except Exception as exc:
        try:
            responder.server_close()
        except Exception:
            pass
        raise XrayCertificationError("local HTTP responder could not be started") from exc
    try:
        server_port = _ephemeral_port()
        socks_port = _ephemeral_port()
        while socks_port == server_port:
            socks_port = _ephemeral_port()
        try:
            configs = _configs(server_port, socks_port, str(uuid.uuid4()))
        except (TypeError, ValueError) as exc:
            raise XrayCertificationError("generated Xray configuration could not be created") from exc
        try:
            validate_configs(configs, binary=executable)
        except RuntimeError as exc:
            raise XrayCertificationError(f"generated Xray configuration failed validation: {exc}") from exc

        with tempfile.TemporaryDirectory(prefix="transitvpn-xray-certification-") as directory:
            root = Path(directory)
            server_config = root / "server.json"
            client_config = root / "client.json"
            _write_config(server_config, configs["server"])
            _write_config(client_config, configs["client"])

            deadline = time.monotonic() + timeout
            server_process = _start(executable, server_config, "server")
            _wait_ready(server_process, server_port, "server", deadline)
            client_process = _start(executable, client_config, "client")
            _wait_ready(client_process, socks_port, "client", deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise XrayCertificationError("application-data tunnel probe timed out")
            try:
                response_bytes = _probe(
                    socks_port, int(responder.server_address[1]), response_body, remaining
                )
            except XrayCertificationError as exc:
                for role, process in (("server", server_process), ("client", client_process)):
                    return_code = process.poll()
                    if return_code is not None:
                        raise XrayCertificationError(
                            f"{role} Xray process exited during certification "
                            f"(code {return_code})"
                        ) from exc
                raise
            for role, process in (("server", server_process), ("client", client_process)):
                return_code = process.poll()
                if return_code is not None:
                    raise XrayCertificationError(
                        f"{role} Xray process exited during certification (code {return_code})"
                    )
            return XrayTunnelCertification(XRAY_VERSION, response_bytes)
    finally:
        cleanup_failed = False
        try:
            _stop_all(client_process, server_process)
        except Exception:
            cleanup_failed = True
        if not _stop_responder(responder, responder_thread):
            cleanup_failed = True
        if cleanup_failed:
            raise XrayCertificationError("Xray certification cleanup could not be confirmed")
