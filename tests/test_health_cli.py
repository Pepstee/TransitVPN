"""HTTP health CLI coverage through the configured local Xray SOCKS client."""

from __future__ import annotations

import io
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

import pytest

from tests.test_import_profile import _port_is_closed
from tests.test_xray_local_tunnel_certification import _write_local_target_certificate
from transitvpn import cli
from transitvpn import xray_certification as certification

REPOSITORY = Path(__file__).resolve().parents[1]


class _TruncatedHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.request_count += 1  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "40")
        self.end_headers()
        self.wfile.write(b"short")
        self.wfile.flush()

    def log_message(self, format: str, *args: object) -> None:
        return


class _TruncatedResponder(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        self.request_count = 0
        super().__init__(("127.0.0.1", 0), _TruncatedHandler)


class _TLSHealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.server.request_count += 1  # type: ignore[attr-defined]
        body = b"verified-local-health"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class _TLSHealthResponder(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, context: ssl.SSLContext, *, handshake_delay: float = 0.0) -> None:
        self.tls_context = context
        self.handshake_delay = handshake_delay
        self.request_count = 0
        super().__init__(("127.0.0.1", 0), _TLSHealthHandler)

    def process_request_thread(self, request: socket.socket, client_address: object) -> None:
        try:
            if self.handshake_delay:
                time.sleep(self.handshake_delay)
            with self.tls_context.wrap_socket(request, server_side=True) as connection:
                super().process_request_thread(connection, client_address)
        except (OSError, ssl.SSLError):
            request.close()


def _run_cli(
    workdir: Path,
    url: str,
    *,
    timeout: float = 5.0,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        environment.pop(name, None)
    environment.update({
        "PYTHONPATH": str(REPOSITORY)
        + os.pathsep
        + os.environ.get("PYTHONPATH", ""),
    })
    if extra_env:
        environment.update(extra_env)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "transitvpn",
            "health",
            "--url",
            url,
            "--timeout",
            str(timeout),
        ],
        cwd=workdir,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def _start_pair(
    workdir: Path,
    executable: str,
    responder_port: int,
    *,
    credential_mismatch: bool = False,
) -> tuple[subprocess.Popen[bytes], subprocess.Popen[bytes], Path, int, int, str]:
    server_port = certification._ephemeral_port()
    socks_port = certification._ephemeral_port()
    while socks_port == server_port or socks_port == responder_port:
        socks_port = certification._ephemeral_port()
    while server_port == responder_port:
        server_port = certification._ephemeral_port()
    client_id = str(uuid.uuid4())
    configs = certification._configs(
        server_port,
        socks_port,
        client_id,
        responder_port=responder_port,
        credential_mismatch=credential_mismatch,
    )
    certification.validate_configs(configs, binary=executable)
    state_dir = workdir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    server_config = state_dir / "xray-server.json"
    client_config = state_dir / "xray-client.json"
    certification._write_config(server_config, configs["server"])
    certification._write_config(client_config, configs["client"])
    server = certification._start(executable, server_config, "test server")
    client: subprocess.Popen[bytes] | None = None
    try:
        certification._wait_ready(
            server, server_port, "test server", time.monotonic() + 10.0
        )
        client = certification._start(executable, client_config, "test client")
        certification._wait_ready(
            client, socks_port, "test client", time.monotonic() + 10.0
        )
    except Exception:
        certification._stop(client)
        certification._stop(server)
        raise
    return server, client, client_config, server_port, socks_port, client_id


class TestHealthCommandUnitTests:
    def test_parser_and_success_record(self) -> None:
        args = cli.build_parser().parse_args(
            ["health", "--url", "http://health.invalid/ready", "--timeout", "2.5"]
        )
        assert args.command == "health"
        assert args.timeout == 2.5
        out, err = io.StringIO(), io.StringIO()
        observation = certification.SocksHTTPObservation(200, 17)
        with (
            mock.patch(
                "transitvpn.xray_certification.probe_configured_socks_http",
                return_value=observation,
            ) as probe,
            redirect_stdout(out),
            redirect_stderr(err),
        ):
            code = cli.main(["health", "--url", "http://health.invalid/ready"])
        record = json.loads(out.getvalue())
        assert code == 0
        assert err.getvalue() == ""
        assert record == {
            "health": "healthy",
            "http_observed": True,
            "http_status": 200,
            "response_bytes": 17,
            "route": "configured_socks",
            "process_liveness": "not_checked",
        }
        probe.assert_called_once_with(
            Path("state") / "xray-client.json",
            "http://health.invalid/ready",
            timeout=5.0,
        )

    def test_explicit_zero_port_is_rejected_before_socket_use(self, tmp_path: Path) -> None:
        for scheme in ("http", "https"):
            with pytest.raises(ValueError, match="URL port"):
                certification.probe_configured_socks_http(
                    tmp_path / "no-config-read-before-url-validation",
                    f"{scheme}://health.invalid:0/ready",
                )

    @pytest.mark.parametrize(
        ("url", "target_host", "port", "host_header", "scheme", "tls_name"),
        [
            ("http://health.invalid/ready", "health.invalid", 80, "health.invalid", "http", "health.invalid"),
            ("https://health.invalid/ready", "health.invalid", 443, "health.invalid", "https", "health.invalid"),
            ("https://health.invalid:8443/ready", "health.invalid", 8443, "health.invalid:8443", "https", "health.invalid"),
            ("https://[::1]/ready", "::1", 443, "[::1]", "https", "::1"),
            ("https://bücher.example/ready", "bücher.example", 443, "xn--bcher-kva.example", "https", "xn--bcher-kva.example"),
        ],
    )
    def test_http_and_https_url_defaults_and_host_routing(
        self,
        tmp_path: Path,
        url: str,
        target_host: str,
        port: int,
        host_header: str,
        scheme: str,
        tls_name: str,
    ) -> None:
        with (
            mock.patch.object(
                certification, "_configured_socks_inbound", return_value=("127.0.0.1", 1080)
            ),
            mock.patch.object(
                certification, "_http_request_over_socks", return_value=(200, b"ok")
            ) as request,
        ):
            result = certification.probe_configured_socks_http(tmp_path / "unused", url)
        assert result == certification.SocksHTTPObservation(200, 2)
        args, kwargs = request.call_args
        assert args[2:7] == (target_host, port, "/ready", host_header, 5.0)
        assert kwargs["scheme"] == scheme
        assert kwargs["tls_server_name"] == tls_name

    @pytest.mark.parametrize(
        "url",
        [
            "ftp://health.invalid/ready",
            "https://user@health.invalid/ready",
            "https://health.invalid/ready#fragment",
            "https://health.invalid:0/ready",
        ],
    )
    def test_unsupported_or_unsafe_health_urls_are_rejected(self, tmp_path: Path, url: str) -> None:
        with pytest.raises(ValueError):
            certification.probe_configured_socks_http(
                tmp_path / "no-config-read-before-url-validation",
                url,
            )


def test_health_cli_reports_positive_and_live_but_broken_xray_route(
    tmp_path: Path,
) -> None:
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError as exc:
        pytest.skip(f"pinned Xray binary is unavailable: {exc}")

    responder_body = b"local-health-ok"
    responder = certification._Responder(responder_body)
    responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
    responder_thread.start()
    server: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    try:
        server, client, client_config, server_port, socks_port, client_id = _start_pair(
            tmp_path, executable, int(responder.server_address[1])
        )
        url = f"http://127.0.0.1:{responder.server_address[1]}/health"

        assert server.poll() is None
        assert client.poll() is None
        positive = _run_cli(tmp_path, url)
        assert positive.returncode == 0, positive.stdout + positive.stderr
        positive_record = json.loads(positive.stdout)
        assert positive_record["health"] == "healthy"
        assert positive_record["http_observed"] is True
        assert positive_record["http_status"] == 200
        assert positive_record["route"] == "configured_socks"
        assert positive_record["process_liveness"] == "not_checked"
        assert responder.request_count == 1

        assert certification._stop(client)
        client = None
        broken_configs = certification._configs(
            server_port,
            socks_port,
            client_id,
            responder_port=int(responder.server_address[1]),
            credential_mismatch=True,
        )
        certification._write_config(client_config, broken_configs["client"])
        client = certification._start(executable, client_config, "broken test client")
        certification._wait_ready(
            client, socks_port, "broken test client", time.monotonic() + 10.0
        )
        assert server.poll() is None
        assert client.poll() is None

        negative = _run_cli(tmp_path, url, timeout=1.5)
        assert negative.returncode == 1
        negative_record = json.loads(negative.stdout)
        assert negative_record["health"] == "unhealthy"
        assert negative_record["http_observed"] is False
        assert negative_record["route"] == "configured_socks"
        assert negative_record["process_liveness"] == "not_checked"
        assert client.poll() is None, "the negative route must fail while Xray remains live"
        assert responder.request_count == 1, "health must not fall back to a direct HTTP request"
    finally:
        certification._stop(client)
        certification._stop(server)
        responder.shutdown()
        responder.server_close()
        responder_thread.join(timeout=2)


def test_health_cli_rejects_real_truncated_http_body_over_xray(tmp_path: Path) -> None:
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError as exc:
        pytest.skip(f"pinned Xray binary is unavailable: {exc}")

    responder = _TruncatedResponder()
    responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
    responder_thread.start()
    server: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    try:
        server, client, _client_config, _server_port, _socks_port, _client_id = _start_pair(
            tmp_path, executable, int(responder.server_address[1])
        )
        url = f"http://127.0.0.1:{responder.server_address[1]}/truncated"
        result = _run_cli(tmp_path, url)
        assert result.returncode == 1
        record = json.loads(result.stdout)
        assert record["health"] == "unhealthy"
        assert record["http_observed"] is True
        assert record["http_status"] == 200
        assert record["response_bytes"] == 5
        assert "body is incomplete" in record["error"]
        assert record["route"] == "configured_socks"
        assert record["process_liveness"] == "not_checked"
        assert responder.request_count == 1
        assert server.poll() is None
        assert client.poll() is None
    finally:
        certification._stop(client)
        certification._stop(server)
        responder.shutdown()
        responder.server_close()
        responder_thread.join(timeout=2)


def test_health_cli_uses_verified_https_through_xray_without_direct_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError as exc:
        pytest.skip(f"pinned Xray binary is unavailable: {exc}")

    certificate_path, key_path = _write_local_target_certificate(tmp_path, "localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(certificate_path), str(key_path))
    responder = _TLSHealthResponder(server_context)
    responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
    responder_thread.start()
    server: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    try:
        server, client, client_config, _server_port, socks_port, _client_id = _start_pair(
            tmp_path, executable, int(responder.server_address[1])
        )
        port = int(responder.server_address[1])
        url = f"https://localhost:{port}/health"
        trusted_environment = {"SSL_CERT_FILE": str(certificate_path)}

        positive = _run_cli(tmp_path, url, extra_env=trusted_environment)
        assert positive.returncode == 0
        positive_record = json.loads(positive.stdout)
        assert positive_record["health"] == "healthy"
        assert positive_record["http_observed"] is True
        assert positive_record["http_status"] == 200
        assert positive_record["route"] == "configured_socks"
        assert positive_record["process_liveness"] == "not_checked"
        assert responder.request_count == 1

        original_context_factory = ssl.create_default_context
        contexts: list[ssl.SSLContext] = []

        def test_trusted_context(*args: object, **kwargs: object) -> ssl.SSLContext:
            context = original_context_factory(*args, **kwargs)
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert context.check_hostname is True
            context.load_verify_locations(cafile=str(certificate_path))
            contexts.append(context)
            return context

        real_getaddrinfo = socket.getaddrinfo

        def reject_target_lookup(host: object, *args: object, **kwargs: object) -> object:
            if host == "localhost":
                raise AssertionError("target hostname was resolved locally")
            return real_getaddrinfo(host, *args, **kwargs)

        with monkeypatch.context() as patch:
            patch.setattr(certification.ssl, "create_default_context", test_trusted_context)
            patch.setattr(certification.socket, "getaddrinfo", reject_target_lookup)
            observation = certification.probe_configured_socks_http(client_config, url)
        assert observation == certification.SocksHTTPObservation(200, len(b"verified-local-health"))
        assert contexts
        assert responder.request_count == 2

        wrong_host = _run_cli(
            tmp_path,
            f"https://127.0.0.1:{port}/health",
            extra_env=trusted_environment,
        )
        assert wrong_host.returncode == 1
        wrong_host_record = json.loads(wrong_host.stdout)
        assert wrong_host_record["health"] == "unhealthy"
        assert wrong_host_record["http_observed"] is False
        assert wrong_host_record["error"] == "verified HTTPS tunnel probe failed"
        assert responder.request_count == 2

        untrusted = _run_cli(tmp_path, url)
        assert untrusted.returncode == 1
        untrusted_record = json.loads(untrusted.stdout)
        assert untrusted_record["health"] == "unhealthy"
        assert untrusted_record["http_observed"] is False
        assert untrusted_record["error"] == "verified HTTPS tunnel probe failed"
        assert responder.request_count == 2

        assert certification._stop(client)
        client = None
        unavailable = _run_cli(tmp_path, url)
        assert unavailable.returncode == 1
        unavailable_record = json.loads(unavailable.stdout)
        assert unavailable_record["health"] == "unhealthy"
        assert unavailable_record["http_observed"] is False
        assert responder.request_count == 2, "health must not bypass a stopped SOCKS client"
        assert server.poll() is None
        assert _port_is_closed(socks_port)
    finally:
        certification._stop(client)
        certification._stop(server)
        responder.shutdown()
        responder.server_close()
        responder_thread.join(timeout=2)


def test_https_handshake_uses_the_health_request_deadline(tmp_path: Path) -> None:
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError as exc:
        pytest.skip(f"pinned Xray binary is unavailable: {exc}")

    certificate_path, key_path = _write_local_target_certificate(tmp_path, "localhost")
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(certificate_path), str(key_path))
    responder = _TLSHealthResponder(server_context, handshake_delay=0.4)
    responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
    responder_thread.start()
    server: subprocess.Popen[bytes] | None = None
    client: subprocess.Popen[bytes] | None = None
    try:
        server, client, _config, _server_port, _socks_port, _client_id = _start_pair(
            tmp_path, executable, int(responder.server_address[1])
        )
        start = time.monotonic()
        result = _run_cli(
            tmp_path,
            f"https://localhost:{responder.server_address[1]}/health",
            timeout=0.2,
            extra_env={"SSL_CERT_FILE": str(certificate_path)},
        )
        elapsed = time.monotonic() - start
        assert result.returncode == 1
        record = json.loads(result.stdout)
        assert record["health"] == "unhealthy"
        assert record["http_observed"] is False
        assert record["error"] == "application-data tunnel probe timed out"
        assert elapsed < 0.35
        assert responder.request_count == 0
        assert server.poll() is None
        assert client.poll() is None
    finally:
        certification._stop(client)
        certification._stop(server)
        responder.shutdown()
        responder.server_close()
        responder_thread.join(timeout=2)
