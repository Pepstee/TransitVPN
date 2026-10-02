"""Local, self-cleaning certification of an Xray server/client data path."""

from __future__ import annotations

import ipaddress
import json
import math
import secrets
import select
import socket
import socketserver
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from transitvpn.xray import XRAY_VERSION, validate_configs, verify_binary

_LOOPBACK = "127.0.0.1"


class XrayCertificationError(RuntimeError):
    """A closed failure of the local Xray tunnel certification."""


class XrayHTTPProbeError(XrayCertificationError):
    """An HTTP response was observed but its framing was invalid or incomplete."""

    def __init__(self, message: str, *, status_code: int, response_bytes: int) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_bytes = response_bytes


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


@dataclass(frozen=True)
class SocksHTTPObservation:
    """Credential-free result of one HTTP request sent only through SOCKS."""

    status_code: int
    response_bytes: int

    def operator_record(self) -> dict[str, object]:
        healthy = 200 <= self.status_code < 300
        return {
            "health": "healthy" if healthy else "unhealthy",
            "http_observed": True,
            "http_status": self.status_code,
            "response_bytes": self.response_bytes,
            "route": "configured_socks",
            "process_liveness": "not_checked",
        }


class _Responder(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, body: bytes) -> None:
        self.response_body = body
        self._request_count = 0
        self._request_count_lock = threading.Lock()
        super().__init__((_LOOPBACK, 0), _RequestHandler)

    @property
    def request_count(self) -> int:
        with self._request_count_lock:
            return self._request_count

    def record_request(self) -> None:
        with self._request_count_lock:
            self._request_count += 1


class _RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self) -> None:
        self.server.record_request()  # type: ignore[attr-defined]
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


def _configs(
    server_port: int,
    socks_port: int,
    client_id: str,
    *,
    responder_port: int | None = None,
    credential_mismatch: bool = False,
) -> dict[str, dict[str, Any]]:
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
    if responder_port is not None:
        # The pinned Xray blocks private destinations on VLESS by default.
        # Permit only this temporary IPv4 responder, never a private subnet.
        server["outbounds"][0]["settings"] = {
            "targetStrategy": "ForceIPv4",
            "finalRules": [{
                "action": "allow", "network": "tcp",
                "ip": [_LOOPBACK + "/32"], "port": str(responder_port),
            }],
        }
    outbound_client_id = str(uuid.uuid4()) if credential_mismatch else client_id
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
                "users": [{"id": outbound_client_id, "encryption": "none"}],
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


def _complete_tls_handshake(
    connection: ssl.SSLSocket, deadline: float
) -> None:
    """Complete verified TLS without extending the SOCKS request deadline."""
    connection.setblocking(False)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise XrayCertificationError("application-data tunnel probe timed out")
        try:
            connection.do_handshake()
            break
        except ssl.SSLWantReadError:
            readable, _, _ = select.select([connection], [], [], remaining)
            if not readable:
                raise XrayCertificationError(
                    "application-data tunnel probe timed out"
                ) from None
        except ssl.SSLWantWriteError:
            _, writable, _ = select.select([], [connection], [], remaining)
            if not writable:
                raise XrayCertificationError(
                    "application-data tunnel probe timed out"
                ) from None
    connection.setblocking(True)
    _set_remaining_timeout(connection, deadline)


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


def _http_request_over_socks(
    socks_host: str,
    socks_port: int,
    target_host: str,
    target_port: int,
    request_target: str,
    host_header: str,
    timeout: float,
    *,
    scheme: str,
    tls_server_name: str,
    target_label: str,
) -> tuple[int, bytes]:
    deadline = time.monotonic() + timeout
    tls_connection: ssl.SSLSocket | None = None
    try:
        try:
            with socket.create_connection(
                (socks_host, socks_port), timeout=timeout
            ) as raw_connection:
                connection: socket.socket = raw_connection
                _set_remaining_timeout(connection, deadline)
                connection.sendall(b"\x05\x01\x00")
                if _receive_exact(connection, 2, deadline) != b"\x05\x00":
                    raise XrayCertificationError("client SOCKS endpoint rejected no-auth negotiation")

                try:
                    address = ipaddress.ip_address(target_host)
                except ValueError:
                    try:
                        hostname = target_host.encode("idna")
                    except UnicodeError as exc:
                        raise XrayCertificationError("HTTP target hostname is invalid") from exc
                    if not hostname or len(hostname) > 255:
                        raise XrayCertificationError("HTTP target hostname is invalid")
                    address_type = b"\x03" + bytes((len(hostname),)) + hostname
                else:
                    address_type = (b"\x01" if address.version == 4 else b"\x04") + address.packed
                request = b"\x05\x01\x00" + address_type + target_port.to_bytes(2, "big")
                connection.sendall(request)
                reply = _receive_exact(connection, 4, deadline)
                if reply[0] != 5 or reply[1] != 0:
                    raise XrayCertificationError(
                        f"client SOCKS endpoint could not reach the {target_label}"
                    )
                address_size = {1: 4, 4: 16}.get(reply[3])
                if reply[3] == 3:
                    address_size = _receive_exact(connection, 1, deadline)[0]
                if address_size is None:
                    raise XrayCertificationError("client SOCKS endpoint returned an invalid address")
                _receive_exact(connection, address_size + 2, deadline)

                if scheme == "https":
                    try:
                        _set_remaining_timeout(connection, deadline)
                        tls_context = ssl.create_default_context()
                        tls_connection = tls_context.wrap_socket(
                            raw_connection,
                            server_hostname=tls_server_name,
                            do_handshake_on_connect=False,
                        )
                        connection = tls_connection
                        _complete_tls_handshake(tls_connection, deadline)
                    except XrayCertificationError:
                        raise
                    except (OSError, ssl.SSLError, ValueError):
                        raise XrayCertificationError(
                            "verified HTTPS tunnel probe failed"
                        ) from None

                _set_remaining_timeout(connection, deadline)
                request_line = f"GET {request_target} HTTP/1.0\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
                connection.sendall(request_line.encode("ascii"))
                response = bytearray()
                while True:
                    _set_remaining_timeout(connection, deadline)
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    if len(response) + len(chunk) > 1_048_576:
                        raise XrayCertificationError("HTTP health response exceeded the bounded size")
                    response.extend(chunk)
        except XrayCertificationError:
            raise
        except Exception as exc:
            raise XrayCertificationError("application-data tunnel probe failed") from exc
    finally:
        if tls_connection is not None:
            try:
                tls_connection.close()
            except OSError:
                pass

    header, separator, body = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise XrayCertificationError("application-data tunnel probe returned an invalid response")
    status_line = header.split(b"\r\n", 1)[0].split()
    if (
        len(status_line) < 2
        or status_line[0] not in {b"HTTP/1.0", b"HTTP/1.1"}
        or len(status_line[1]) != 3
        or not status_line[1].isdigit()
    ):
        raise XrayCertificationError("application-data tunnel probe returned an invalid response")
    status = int(status_line[1])
    headers: dict[bytes, bytes] = {}
    for line in header.split(b"\r\n")[1:]:
        name, separator, value = line.partition(b":")
        if not separator or not name or any(ch <= 32 or ch >= 127 for ch in name):
            raise XrayCertificationError("HTTP health response returned invalid headers")
        key = name.lower()
        value = value.strip()
        previous = headers.get(key)
        if previous is not None and previous != value:
            raise XrayCertificationError("HTTP health response returned conflicting headers")
        headers[key] = value

    content_length = headers.get(b"content-length")
    transfer_encoding = headers.get(b"transfer-encoding")
    if content_length is not None and transfer_encoding is not None:
        raise XrayCertificationError("HTTP health response has ambiguous body framing")
    if transfer_encoding is not None:
        codings = [part.strip().lower() for part in transfer_encoding.split(b",")]
        if codings != [b"chunked"]:
            raise XrayCertificationError("HTTP health response uses unsupported body framing")
        try:
            body = _decode_chunked_body(body)
        except XrayCertificationError as exc:
            raise XrayHTTPProbeError(
                str(exc), status_code=status, response_bytes=0
            ) from exc
    elif content_length is not None:
        if (
            not content_length.isdigit()
            or len(content_length) > 7
            or len(body) != int(content_length)
        ):
            raise XrayHTTPProbeError(
                "HTTP health response body is incomplete",
                status_code=status,
                response_bytes=len(body),
            )
    return status, bytes(body)


def _decode_chunked_body(body: bytes) -> bytes:
    result = bytearray()
    cursor = 0
    while True:
        line_end = body.find(b"\r\n", cursor)
        if line_end < 0:
            raise XrayCertificationError("HTTP health response chunk framing is incomplete")
        size_text = body[cursor:line_end].split(b";", 1)[0].strip()
        if not size_text or any(ch not in b"0123456789abcdefABCDEF" for ch in size_text):
            raise XrayCertificationError("HTTP health response has invalid chunk framing")
        if len(size_text) > 8:
            raise XrayCertificationError("HTTP health response chunk exceeds the bounded size")
        size = int(size_text, 16)
        cursor = line_end + 2
        if size == 0:
            trailer_end = body.find(b"\r\n\r\n", cursor)
            if body[cursor:] == b"\r\n":
                return bytes(result)
            if trailer_end < 0 or trailer_end + 4 != len(body):
                raise XrayCertificationError("HTTP health response chunk framing is incomplete")
            trailer_lines = body[cursor:trailer_end].split(b"\r\n")
            if any(b":" not in line for line in trailer_lines):
                raise XrayCertificationError("HTTP health response has invalid chunk trailers")
            return bytes(result)
        chunk_end = cursor + size
        if chunk_end + 2 > len(body) or body[chunk_end:chunk_end + 2] != b"\r\n":
            raise XrayCertificationError("HTTP health response chunk framing is incomplete")
        result.extend(body[cursor:chunk_end])
        if len(result) > 1_048_576:
            raise XrayCertificationError("HTTP health response exceeded the bounded size")
        cursor = chunk_end + 2


def _configured_socks_inbound(client_config_path: str | Path) -> tuple[str, int]:
    try:
        config = json.loads(Path(client_config_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise XrayCertificationError("configured Xray client settings are unavailable") from exc
    if not isinstance(config, dict) or not isinstance(config.get("inbounds"), list):
        raise XrayCertificationError("configured Xray client settings are invalid")
    inbounds = [x for x in config["inbounds"] if isinstance(x, dict) and x.get("protocol") == "socks"]
    if len(inbounds) != 1:
        raise XrayCertificationError("configured Xray client must have exactly one SOCKS inbound")
    inbound = inbounds[0]
    listen = inbound.get("listen")
    port = inbound.get("port")
    if not isinstance(listen, str):
        raise XrayCertificationError("configured SOCKS inbound must listen on loopback")
    try:
        address = ipaddress.ip_address(listen)
    except ValueError as exc:
        raise XrayCertificationError("configured SOCKS inbound must listen on loopback") from exc
    if not address.is_loopback:
        raise XrayCertificationError("configured SOCKS inbound must listen on loopback")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise XrayCertificationError("configured SOCKS inbound has an invalid port")
    return str(address), port


def probe_configured_socks_http(
    client_config_path: str | Path,
    url: str,
    *,
    timeout: float = 5.0,
) -> SocksHTTPObservation:
    """Observe an HTTP or HTTPS response through the configured loopback SOCKS client.

    Only the local SOCKS listener is connected to directly. The target host is
    carried in the SOCKS CONNECT request so its DNS and route stay behind Xray.
    Process liveness is deliberately not consulted.
    """
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
        or timeout > 30
    ):
        raise ValueError("timeout must be positive, finite, and at most 30 seconds")
    if (
        not isinstance(url, str)
        or not url
        or len(url) > 8192
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in url)
    ):
        raise ValueError("URL is invalid")
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        port = parsed.port if parsed.port is not None else (
            443 if scheme == "https" else 80
        )
    except ValueError as exc:
        raise ValueError("URL is invalid") from exc
    if (
        scheme not in {"http", "https"}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError("health URL must use HTTP or HTTPS without user information")
    if parsed.fragment or not parsed.hostname:
        raise ValueError("health URL must include a host and no fragment")
    if not 1 <= port <= 65535:
        raise ValueError("health URL port is invalid")
    target_host = parsed.hostname
    try:
        host_ascii = target_host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("health URL host is invalid") from exc
    try:
        host_ip = ipaddress.ip_address(target_host)
    except ValueError:
        host_header = host_ascii
    else:
        host_header = f"[{host_ascii}]" if host_ip.version == 6 else host_ascii
    if parsed.port is not None:
        host_header += f":{port}"
    request_target = parsed.path or "/"
    if parsed.query:
        request_target += "?" + parsed.query
    if any(ch in request_target for ch in "\r\n"):
        raise ValueError("health URL path is invalid")
    request_target = quote(request_target, safe="/%?:@!$&'()*+,;=-._~")
    socks_host, socks_port = _configured_socks_inbound(client_config_path)
    status, body = _http_request_over_socks(
        socks_host,
        socks_port,
        target_host,
        port,
        request_target,
        host_header,
        timeout,
        scheme=scheme,
        tls_server_name=host_ascii,
        target_label="health target",
    )
    return SocksHTTPObservation(status_code=status, response_bytes=len(body))


def _probe(socks_port: int, upstream_port: int, expected_body: bytes, timeout: float) -> int:
    status, body = _http_request_over_socks(
        _LOOPBACK,
        socks_port,
        "localhost",
        upstream_port,
        "/certify",
        "local",
        timeout,
        scheme="http",
        tls_server_name="localhost",
        target_label="the responder",
    )
    if status != 200 or body != expected_body:
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
    except Exception:  # noqa: BLE001 -- teardown errors become an unconfirmed-stop result without exception details.
        return False


def _stop_all(*processes: subprocess.Popen[bytes] | None) -> None:
    """Attempt every child cleanup and fail closed unless all exits are observed."""
    stopped = True
    for process in processes:
        try:
            stopped = _stop(process) and stopped
        except Exception:  # noqa: BLE001 -- attempt every child; the final error is generic if any exit is unconfirmed.
            stopped = False
    if not stopped:
        raise XrayCertificationError("Xray process cleanup could not be confirmed")


def _stop_responder(responder: socketserver.TCPServer, thread: threading.Thread) -> bool:
    stopped = True
    for operation in (responder.shutdown, responder.server_close):
        try:
            operation()
        except Exception:  # noqa: BLE001 -- try the remaining responder cleanup operations and report only failure.
            stopped = False
    try:
        thread.join(timeout=2)
        if thread.is_alive():
            stopped = False
    except Exception:  # noqa: BLE001 -- responder shutdown failure is reported generically to preserve startup failure privacy.
        stopped = False
    return stopped


def certify_local_tunnel(
    xray_binary: str = "xray",
    *,
    timeout: float = 10.0,
    credential_mismatch: bool = False,
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
        except Exception:  # noqa: BLE001, S110 -- keep the fixed startup error; suppress cleanup detail.
            pass
        raise XrayCertificationError("local HTTP responder could not be started") from exc
    try:
        server_port = _ephemeral_port()
        socks_port = _ephemeral_port()
        while socks_port == server_port:
            socks_port = _ephemeral_port()
        try:
            configs = _configs(
                server_port, socks_port, str(uuid.uuid4()),
                responder_port=int(responder.server_address[1]),
                credential_mismatch=credential_mismatch,
            )
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
        except Exception:  # noqa: BLE001 -- finish other cleanup and raise only the fixed cleanup error.
            cleanup_failed = True
        if not _stop_responder(responder, responder_thread):
            cleanup_failed = True
        if cleanup_failed:
            raise XrayCertificationError("Xray certification cleanup could not be confirmed")
