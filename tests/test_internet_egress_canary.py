"""Opt-in real Internet HTTPS egress canary for the managed tunnel roles.

Default test runs remain offline: this canary is skipped unless the operator
explicitly sets TRANSITVPN_EGRESS_CANARY=1, and a skipped canary is never
treated as passed. When opted in, the managed server inbound, the imported
client SOCKS listener and a fresh TLS 1.3 REALITY cover fixture all stay on
IPv4 127.0.0.1, and exactly one kind of remote request is made: a bounded,
unauthenticated GET to https://example.com/ on TCP 443 through the client's
loopback SOCKS listener with an ordinary curl client, using socks5h so DNS
resolves behind the tunnel, with certificate verification enabled and no
redirects or POSTs. No public or LAN listener is opened.
"""

from __future__ import annotations

import os
import shutil
import ssl
import stat
import subprocess
import sys
import threading
import unittest
from pathlib import Path

import pytest

from tests.test_import_profile import (
    _LOOPBACK,
    REPOSITORY,
    _port_is_closed,
    _wait_port_open,
)
from tests.test_xray_local_tunnel_certification import (
    _assert_absent_from_repository,
    _RealityTarget,
    _write_local_target_certificate,
)
from transitvpn import xray as xray_module
from transitvpn import xray_certification as certification
from transitvpn.config import XrayDeployment
from transitvpn.keygen import generate_keys, generate_short_id
from transitvpn.server import build_client_config, build_server_config
from transitvpn.tunnel import get_status

_OPT_IN_ENV = "TRANSITVPN_EGRESS_CANARY"
_EGRESS_HOST = "example.com"
_EGRESS_URL = "https://" + _EGRESS_HOST + "/"
_EGRESS_PORT = "443"
_PROXY_ENV_KEYS = (
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY",
    "no_proxy", "NO_PROXY",
)
_POSITIVE_MAX_TIME = 20.0
_NEGATIVE_MAX_TIME = 10.0
_CLI_TIMEOUT = 30


def _curl_environment() -> dict[str, str]:
    """Drop every proxy selector and curl configuration source."""
    environment = dict(os.environ)
    for name in (*_PROXY_ENV_KEYS, "CURL_HOME", "XDG_CONFIG_HOME"):
        environment.pop(name, None)
    return environment


def _curl_through_client_socks(
    curl: str, socks_port: int, *, max_time: float
) -> subprocess.CompletedProcess[str]:
    """One bounded GET via socks5h with TLS verification; no redirects or POSTs."""
    command = [
        curl, "-q",
        "--silent", "--show-error",
        "--output", os.devnull,
        "--write-out", "%{http_code} %{ssl_verify_result}",
        "--request", "GET",
        "--proxy", "socks5h://127.0.0.1:" + str(socks_port),
        "--max-time", str(max_time),
        _EGRESS_URL,
    ]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=_curl_environment(),
        timeout=max_time + 5.0,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def test_opt_in_real_internet_https_egress_canary(tmp_path: Path) -> None:
    if os.environ.get(_OPT_IN_ENV) != "1":
        pytest.skip(
            "opt-in Internet egress canary not requested; a skipped canary is "
            "not a pass; set " + _OPT_IN_ENV + "=1 to authorise one bounded "
            "GET to https://example.com/"
        )
    curl = shutil.which("curl")
    if curl is None:
        pytest.fail("opt-in Internet egress canary requested but curl is unavailable")
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError:
        pytest.fail(
            "opt-in Internet egress canary requires the pinned Xray binary",
            pytrace=False,
        )

    keys = generate_keys()
    server_short_id = generate_short_id()
    server_name = "cover.example.test"
    outputs: list[str] = []
    server_workdir = tmp_path / "server"
    client_workdir = tmp_path / "client"
    server_workdir.mkdir(mode=0o700)
    client_workdir.mkdir(mode=0o700)
    profile_path = server_workdir / "private-export" / "client.vless"
    target = None
    target_thread = None
    server_port: int | None = None
    socks_port: int | None = None

    def run_cli(workdir: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, "-m", "transitvpn", *arguments],
            capture_output=True,
            text=True,
            cwd=str(workdir),
            env={
                **os.environ,
                "PYTHONPATH": str(REPOSITORY),
                "TRANSITVPN_PROXY_BIN": executable,
                "TRANSITVPN_XRAY_BIN": executable,
            },
            timeout=_CLI_TIMEOUT,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        outputs.extend((result.stdout, result.stderr))
        return result

    def assert_https_ok(socks: int, label: str) -> None:
        request = _curl_through_client_socks(curl, socks, max_time=_POSITIVE_MAX_TIME)
        outputs.extend((request.stdout, request.stderr))
        assert request.returncode == 0, label + " egress request failed"
        assert request.stdout.split() == ["200", "0"], (
            label + " egress request was not a verified HTTPS 200"
        )

    def assert_https_unavailable(socks: int, label: str) -> None:
        request = _curl_through_client_socks(curl, socks, max_time=_NEGATIVE_MAX_TIME)
        outputs.extend((request.stdout, request.stderr))
        assert request.returncode != 0, (
            label + " egress unexpectedly succeeded without the managed server"
        )

    cleanup_failed = False
    try:
        certificate_path, key_path = _write_local_target_certificate(
            tmp_path, server_name
        )
        target_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        target_tls.minimum_version = ssl.TLSVersion.TLSv1_3
        target_tls.maximum_version = ssl.TLSVersion.TLSv1_3
        target_tls.load_cert_chain(str(certificate_path), str(key_path))
        target = _RealityTarget(target_tls)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        target_thread.start()

        used = {int(target.server_address[1])}

        def fresh_port() -> int:
            while True:
                port = certification._ephemeral_port()
                if port not in used:
                    used.add(port)
                    return port

        server_port = fresh_port()
        socks_port = fresh_port()
        deployment = XrayDeployment(
            keys=keys,
            server=_LOOPBACK,
            target=f"{_LOOPBACK}:{target.server_address[1]}",
            server_name=server_name,
            short_id=server_short_id,
            target_verified=True,
            port=server_port,
            socks_port=socks_port,
        )
        server_config = build_server_config(deployment)
        server_config["inbounds"][0]["listen"] = _LOOPBACK
        server_config["outbounds"] = [
            {
                "protocol": "freedom",
                "tag": "egress-example-https",
                "settings": {"targetStrategy": "ForceIPv4"},
            },
            {
                "protocol": "blackhole",
                "tag": "block-other-egress",
                "settings": {},
            },
        ]
        server_config["routing"] = {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "domain": ["full:" + _EGRESS_HOST],
                    "network": "tcp",
                    "port": _EGRESS_PORT,
                    "outboundTag": "egress-example-https",
                },
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "outboundTag": "block-other-egress",
                },
            ],
        }
        client_config = build_client_config(deployment)
        validation = xray_module.validate_configs(
            {"server": server_config, "client": client_config}, binary=executable
        )
        assert validation["version"] == xray_module.XRAY_VERSION

        server_state = server_workdir / "state"
        server_state.mkdir(mode=0o700)
        certification._write_config(server_state / "xray-server.json", server_config)
        certification._write_config(server_state / "xray-client.json", client_config)

        server_up = run_cli(server_workdir, "up")
        assert server_up.returncode == 0
        _wait_port_open(server_port)

        exported = run_cli(
            server_workdir, "export-profile", "--output", str(profile_path)
        )
        assert exported.returncode == 0
        profile_before = profile_path.read_bytes()

        imported = run_cli(
            client_workdir,
            "import-profile",
            "--input",
            str(profile_path),
            "--socks-port",
            str(socks_port),
        )
        assert imported.returncode == 0
        if profile_path.read_bytes() != profile_before:
            raise AssertionError("import modified the profile")
        client_config_path = client_workdir / "state" / "xray-client.json"
        assert stat.S_IMODE(client_config_path.stat().st_mode) == 0o600

        client_up = run_cli(client_workdir, "up", "--client")
        assert client_up.returncode == 0
        _wait_port_open(socks_port)

        assert_https_ok(socks_port, "initial")

        server_down = run_cli(server_workdir, "down")
        assert server_down.returncode == 0
        client_status = run_cli(client_workdir, "status", "--client")
        assert "status: live process (pid=" in client_status.stdout
        assert_https_unavailable(socks_port, "server-down")

        server_up_again = run_cli(server_workdir, "up")
        assert server_up_again.returncode == 0
        _wait_port_open(server_port)
        assert_https_ok(socks_port, "restored")

        final_client_down = run_cli(client_workdir, "down", "--client")
        assert final_client_down.returncode == 0
        final_server_down = run_cli(server_workdir, "down")
        assert final_server_down.returncode == 0
        assert get_status(
            str(client_workdir / "state"), pid_name="tunnel-client.pid"
        ) == (False, None)
        assert get_status(str(server_workdir / "state")) == (False, None)
    finally:
        for workdir, arguments in (
            (client_workdir, ("down", "--client")),
            (server_workdir, ("down",)),
        ):
            try:
                if run_cli(workdir, *arguments).returncode != 0:
                    cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        try:
            if get_status(
                str(client_workdir / "state"), pid_name="tunnel-client.pid"
            )[0]:
                cleanup_failed = True
            if get_status(str(server_workdir / "state"))[0]:
                cleanup_failed = True
        except (OSError, RuntimeError, ValueError):
            cleanup_failed = True
        for listener_port in (server_port, socks_port):
            try:
                if listener_port is not None and not _port_is_closed(listener_port):
                    cleanup_failed = True
            except OSError:
                cleanup_failed = True
        if target is not None:
            try:
                if target_thread is not None:
                    if not certification._stop_responder(target, target_thread):
                        cleanup_failed = True
                else:
                    target.server_close()
            except (OSError, RuntimeError):
                cleanup_failed = True
        profile_uri_text = ""
        try:
            if profile_path.is_file():
                profile_uri_text = profile_path.read_text(encoding="utf-8").strip()
        except OSError:
            cleanup_failed = True
        generated_secrets = (
            keys.vless_uuid,
            keys.reality_private_key,
            keys.reality_public_key,
            keys.ss_password,
            server_short_id,
            *((profile_uri_text,) if profile_uri_text else ()),
        )
        secret_scan_failed = any(
            secret in output for secret in generated_secrets for output in outputs
        )
        try:
            _assert_absent_from_repository(unittest.TestCase(), generated_secrets)
        except (AssertionError, OSError, UnicodeError):
            secret_scan_failed = True
        active_exception = sys.exc_info()[1]
        if active_exception is not None:
            if cleanup_failed:
                active_exception.add_note("egress canary cleanup was incomplete")
            if secret_scan_failed:
                active_exception.add_note(
                    "generated credential scan failed; values withheld"
                )
        elif cleanup_failed:
            raise AssertionError("egress canary cleanup was incomplete")
        elif secret_scan_failed:
            raise AssertionError("generated credential scan failed; values withheld")
