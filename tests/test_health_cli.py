"""HTTP health CLI coverage through the configured local Xray SOCKS client."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid
from unittest import mock

import pytest

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


def _run_cli(workdir: Path, url: str, *, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    environment = {
        **os.environ,
        "PYTHONPATH": str(REPOSITORY)
        + os.pathsep
        + os.environ.get("PYTHONPATH", ""),
    }
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
        with pytest.raises(ValueError, match="URL port"):
            certification.probe_configured_socks_http(
                tmp_path / "no-config-read-before-url-validation",
                "http://health.invalid:0/ready",
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
