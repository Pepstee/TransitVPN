"""Focused coverage for client-profile import and the managed client role."""

from __future__ import annotations

import json
import os
import secrets
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import pytest

from tests.test_xray_local_tunnel_certification import (
    _assert_absent_from_repository,
    _RealityTarget,
    _write_local_target_certificate,
)
from transitvpn import cli
from transitvpn.config import XrayDeployment
from transitvpn.export_profile import build_profile_uri
from transitvpn.import_profile import (
    ProfileImportError,
    build_client_config,
    import_profile,
    parse_profile_uri,
)
from transitvpn.keygen import generate_keys, generate_short_id
from transitvpn.server import build_client_config as build_generated_client

REPOSITORY = Path(__file__).resolve().parents[1]
_LOOPBACK = "127.0.0.1"
_DEFAULT_SOCKS_PORT = 10808


def _generated_pair(socks_port: int = _DEFAULT_SOCKS_PORT):
    keys = generate_keys()
    deployment = XrayDeployment(
        keys=keys,
        server="server.example.test",
        target="cover.example.test:443",
        server_name="cover.example.test",
        short_id=generate_short_id(),
        target_verified=True,
        port=443,
        socks_port=socks_port,
    )
    config = build_generated_client(deployment)
    uri = build_profile_uri(config)
    return config, uri, keys


class TestParseProfileUri(unittest.TestCase):
    def test_round_trip_reconstructs_the_exported_client(self) -> None:
        config, uri, _keys = _generated_pair()
        fields = parse_profile_uri(uri)
        self.assertTrue(
            build_client_config(fields, socks_port=_DEFAULT_SOCKS_PORT) == config,
            "reconstructed client config differs from exported config",
        )

    def test_blank_flow_is_accepted_and_omitted(self) -> None:
        _config, uri, _keys = _generated_pair()
        prefix, _, query = uri.partition("?")
        query_pairs = query.split("&")
        self.assertTrue(
            any(pair.partition("=")[0] == "flow" for pair in query_pairs),
            "generated profile lacks the flow field used by this omission test",
        )
        query_without_flow = "&".join(
            pair for pair in query_pairs if pair.partition("=")[0] != "flow"
        )
        fields = parse_profile_uri(prefix + "?" + query_without_flow)
        self.assertEqual(fields["flow"], "")
        rebuilt = build_client_config(fields, socks_port=_DEFAULT_SOCKS_PORT)
        user = rebuilt["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        self.assertNotIn("flow", user)

    def test_unsupported_and_malformed_profiles_are_rejected(self) -> None:
        _config, uri, keys = _generated_pair()
        prefix, _, query = uri.partition("?")
        good = dict(pair.split("=", 1) for pair in query.split("&"))

        def with_query(**overrides: str) -> str:
            values = {**good, **overrides}
            return prefix + "?" + "&".join(f"{k}={v}" for k, v in values.items())

        variants = [
            with_query(security="tls"),
            with_query(encryption="aes-128-gcm"),
            with_query(type="grpc"),
            with_query(type="ws"),
            with_query(sni=""),
            with_query(sni="bad name"),
            with_query(sid="zz" + good["sid"][2:]),
            with_query(sid=""),
            with_query(pbk="short"),
            with_query(pbk="a" * 44),
            with_query(fp=""),
            with_query(fp="Chrome Fingerprint"),
            with_query(flow="xtls-rprx-direct"),
            prefix + "?" + query + "&sni=other.example.test",
            prefix + "?" + query + "&alpn=h2",
            prefix + "?" + query.replace("flow=", "flow=x&flow="),
            uri + "#fragment",
            prefix + "/path?" + query,
            prefix.rsplit(":", 1)[0] + "?" + query,
            uri.replace(keys.vless_uuid + "@", keys.vless_uuid + ":secret@"),
            uri.replace(keys.vless_uuid, keys.vless_uuid.upper()),
            "https://" + uri.split("://", 1)[1],
        ]
        for variant in variants:
            with self.subTest(variant="structured-rejection"), self.assertRaises(
                ProfileImportError
            ):
                parse_profile_uri(variant)


class TestImportProfileIO(unittest.TestCase):
    def test_import_writes_private_config_and_keeps_input(self) -> None:
        _config, uri, _keys = _generated_pair(socks_port=10999)
        with tempfile.TemporaryDirectory(prefix="transitvpn-import-") as directory:
            root = Path(directory)
            source = root / "export" / "client.vless"
            source.parent.mkdir(mode=0o700)
            source.write_text(uri + "\n", encoding="utf-8")
            source.chmod(0o600)
            before = source.read_bytes()
            output = root / "state" / "xray-client.json"
            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                return_value={"version": "test", "sha256": "0" * 64},
            ):
                import_profile(source, output, socks_port=10999)
            self.assertTrue(source.read_bytes() == before, "import modified its input profile")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(output.parent.stat().st_mode), 0o700)
            parsed_config = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(parsed_config["inbounds"][0]["port"], 10999)
            self.assertEqual(parsed_config["inbounds"][0]["listen"], "127.0.0.1")
            self.assertEqual(len(parsed_config["outbounds"]), 1)
            self.assertEqual(parsed_config["outbounds"][0]["tag"], "proxy")

    def test_import_refusals_preserve_state(self) -> None:
        _config, uri, _keys = _generated_pair()
        with tempfile.TemporaryDirectory(prefix="transitvpn-import-refuse-") as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            profile = private / "client.vless"
            profile.write_text(uri + "\n", encoding="utf-8")
            profile.chmod(0o600)
            linked = private / "linked.vless"
            linked.symlink_to(profile)
            validation = mock.patch(
                "transitvpn.import_profile.validate_configs",
                return_value={"version": "test", "sha256": "0" * 64},
            )
            with validation:
                with self.assertRaises(ProfileImportError):
                    import_profile(linked, root / "out1" / "xray-client.json")
                readable = private / "readable.vless"
                readable.write_text(uri + "\n", encoding="utf-8")
                readable.chmod(0o644)
                with self.assertRaises(ProfileImportError):
                    import_profile(readable, root / "out2" / "xray-client.json")
                output = root / "state" / "xray-client.json"
                import_profile(profile, output, socks_port=_DEFAULT_SOCKS_PORT)
                existing = output.read_bytes()
                with self.assertRaises(ProfileImportError):
                    import_profile(profile, output, socks_port=_DEFAULT_SOCKS_PORT)
                self.assertTrue(
                    output.read_bytes() == existing,
                    "refused import changed the existing client config",
                )
                self.assertFalse((root / "out1").exists())
                self.assertFalse((root / "out2").exists())
            oversized = private / "large.vless"
            oversized.write_text("vless://" + "a" * 9000 + "\n", encoding="utf-8")
            oversized.chmod(0o600)
            with self.assertRaises(ProfileImportError):
                import_profile(oversized, root / "out3" / "xray-client.json")
            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                side_effect=RuntimeError("invalid"),
            ), self.assertRaises(ProfileImportError):
                import_profile(profile, root / "out4" / "xray-client.json")
            self.assertFalse((root / "out4").exists())


def _cli_harness(proxy_binary: str | None) -> str:
    harness = (
        "import sys; "
        "import transitvpn.import_profile as import_profile; "
        "import transitvpn.tunnel as tunnel; "
        "import_profile.validate_configs = lambda configs, binary: "
        "{'version': 'test', 'sha256': '0' * 64}; "
    )
    if proxy_binary is not None:
        harness += f"tunnel.verify_binary = lambda binary: ({proxy_binary!r}, None); "
    harness += "from transitvpn.cli import main; raise SystemExit(main(sys.argv[1:]))"
    return harness


def _run_cli(
    arguments: list[str], workdir: Path, *, proxy_binary: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", _cli_harness(proxy_binary), *arguments],
        capture_output=True,
        text=True,
        cwd=str(workdir),
        env={**os.environ, "PYTHONPATH": str(REPOSITORY)},
        timeout=30,
        stdin=subprocess.DEVNULL,
        check=False,
    )


def test_import_profile_parser_defaults() -> None:
    args = cli.build_parser().parse_args(["import-profile", "--input", "p.vless"])
    assert args.command == "import-profile"
    assert args.socks_port == 10808
    client_args = cli.build_parser().parse_args(["up", "--client"])
    assert client_args.client is True


def test_import_cli_creates_private_client_state(tmp_path: Path) -> None:
    _config, uri, keys = _generated_pair()
    secure = tmp_path / "secure"
    secure.mkdir(mode=0o700)
    profile = secure / "client.vless"
    profile.write_text(uri + "\n", encoding="utf-8")
    profile.chmod(0o600)
    result = _run_cli(["import-profile", "--input", str(profile)], tmp_path)
    assert result.returncode == 0
    assert result.stdout == "import-profile: client profile imported and validated\n"
    assert result.stderr == ""
    output = tmp_path / "state" / "xray-client.json"
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    config = json.loads(output.read_text(encoding="utf-8"))
    if config != build_client_config(parse_profile_uri(uri)):
        raise AssertionError("imported client config differs from parsed profile")
    assert all(
        secret not in result.stdout + result.stderr
        for secret in (uri, keys.vless_uuid, keys.reality_public_key)
    )
    refusal = _run_cli(["import-profile", "--input", str(profile)], tmp_path)
    assert refusal.returncode == 1
    assert refusal.stderr == (
        "import-profile: error: client profile could not be imported\n"
    )
    assert refusal.stdout == ""
    if json.loads(output.read_text(encoding="utf-8")) != config:
        raise AssertionError("refused import changed the existing client config")


def test_import_cli_rejects_invalid_socks_port_before_reading_input(tmp_path: Path) -> None:
    for port in ("0", "65536", "-1"):
        result = _run_cli(
            ["import-profile", "--input", "missing.vless", "--socks-port", port],
            tmp_path,
        )
        assert result.returncode == 2
        assert "--socks-port" in result.stderr
    assert not (tmp_path / "state").exists()


def test_import_cli_missing_input_is_a_generic_refusal(tmp_path: Path) -> None:
    result = _run_cli(
        ["import-profile", "--input", str(tmp_path / "nope.vless")], tmp_path
    )
    assert result.returncode == 1
    assert result.stderr == (
        "import-profile: error: client profile could not be imported\n"
    )


def _write_test_binary(path: Path) -> str:
    path.write_text(f"#!{sys.executable}\nimport time; time.sleep(30)\n")
    path.chmod(0o700)
    return str(path)


def _wait_recorded_pid_gone(pid: int, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def role_workdir(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    (state / "xray-server.json").write_text(json.dumps({"server": True}))
    (state / "xray-client.json").write_text(json.dumps({"client": True}))
    return tmp_path


def test_client_and_server_roles_keep_separate_process_records(
    tmp_path: Path, role_workdir: Path
) -> None:
    proxy = _write_test_binary(tmp_path / "fake-proxy")
    up_server = _run_cli(["up"], role_workdir, proxy_binary=proxy)
    assert up_server.returncode == 0
    up_client = _run_cli(["up", "--client"], role_workdir, proxy_binary=proxy)
    assert up_client.returncode == 0
    state = role_workdir / "state"
    server_pid = json.loads((state / "tunnel.pid").read_text(encoding="utf-8"))["pid"]
    client_pid = json.loads(
        (state / "tunnel-client.pid").read_text(encoding="utf-8")
    )["pid"]
    assert server_pid != client_pid
    status_server = _run_cli(["status"], role_workdir, proxy_binary=proxy)
    assert "status: live process (pid=" in status_server.stdout
    status_client = _run_cli(["status", "--client"], role_workdir, proxy_binary=proxy)
    assert "status: live process (pid=" in status_client.stdout
    down_client = _run_cli(["down", "--client"], role_workdir, proxy_binary=proxy)
    assert down_client.returncode == 0
    assert not (state / "tunnel-client.pid").exists()
    assert (state / "tunnel.pid").exists()
    assert _wait_recorded_pid_gone(client_pid)
    after_client_down = _run_cli(["status"], role_workdir, proxy_binary=proxy)
    assert "status: live process (pid=" in after_client_down.stdout
    still_client = _run_cli(["status", "--client"], role_workdir, proxy_binary=proxy)
    assert "status: not running" in still_client.stdout
    down_server = _run_cli(["down"], role_workdir, proxy_binary=proxy)
    assert down_server.returncode == 0
    assert not (state / "tunnel.pid").exists()
    assert _wait_recorded_pid_gone(server_pid)


def test_client_up_without_imported_config_fails_safely(tmp_path: Path) -> None:
    proxy = _write_test_binary(tmp_path / "fake-proxy")
    empty = tmp_path / "empty"
    empty.mkdir()
    result = _run_cli(["up", "--client"], empty, proxy_binary=proxy)
    assert result.returncode == 1
    assert result.stdout.startswith("up: error: config not found")
    assert not (empty / "state" / "tunnel-client.pid").exists()


def _wait_port_open(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((_LOOPBACK, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.025)
    raise AssertionError("managed listener did not become ready")


def _port_is_closed(port: int, timeout: float = 0.2) -> bool:
    try:
        connection = socket.create_connection((_LOOPBACK, port), timeout=timeout)
    except OSError:
        return True
    connection.close()
    return False


def test_pinned_xray_import_profile_workflow_canary(tmp_path: Path) -> None:
    from transitvpn import xray as xray_module
    from transitvpn import xray_certification as certification
    from transitvpn.tunnel import get_status

    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError as exc:
        pytest.skip(f"pinned Xray binary is unavailable: {exc}")

    body_secret = secrets.token_hex(24)
    body = ("transitvpn-import-workflow:" + body_secret).encode("ascii")
    server_name = "cover.example.test"
    outputs: list[str] = []
    generated_secrets: set[str] = set()
    server_workdir = tmp_path / "server"
    client_workdir = tmp_path / "client"
    server_workdir.mkdir(mode=0o700)
    client_workdir.mkdir(mode=0o700)
    responder = None
    target = None
    responder_thread = None
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
            timeout=30,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        outputs.extend((result.stdout, result.stderr))
        return result

    profile_path = server_workdir / "private-export" / "client.vless"
    cleanup_failed = False
    try:
        certificate_path, key_path = _write_local_target_certificate(
            tmp_path, server_name
        )
        target_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        target_tls.minimum_version = ssl.TLSVersion.TLSv1_3
        target_tls.maximum_version = ssl.TLSVersion.TLSv1_3
        target_tls.load_cert_chain(str(certificate_path), str(key_path))
        responder = certification._Responder(body)
        target = _RealityTarget(target_tls)
        responder_thread = threading.Thread(
            target=responder.serve_forever, daemon=True
        )
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        responder_thread.start()
        target_thread.start()

        # The --target-verified assertion below follows an actual trusted
        # TLS 1.3 handshake to this fresh loopback cover fixture.
        target_context = ssl.create_default_context(cafile=str(certificate_path))
        target_context.minimum_version = ssl.TLSVersion.TLSv1_3
        target_context.maximum_version = ssl.TLSVersion.TLSv1_3
        with (
            socket.create_connection(target.server_address, timeout=3) as raw,
            target_context.wrap_socket(raw, server_hostname=server_name) as tls,
        ):
            assert tls.version() == "TLSv1.3"

        used = {int(responder.server_address[1]), int(target.server_address[1])}

        def fresh_port() -> int:
            while True:
                port = certification._ephemeral_port()
                if port not in used:
                    used.add(port)
                    return port

        server_port = fresh_port()
        socks_port = fresh_port()
        bootstrapped = run_cli(
            server_workdir,
            "bootstrap",
            "--host", _LOOPBACK,
            "--listen", _LOOPBACK,
            "--port", str(server_port),
            "--socks-port", str(socks_port),
            "--target", f"{_LOOPBACK}:{target.server_address[1]}",
            "--server-name", server_name,
            "--target-verified",
            "--xray-binary", executable,
        )
        assert bootstrapped.returncode == 0
        server_state = server_workdir / "state"
        server_config = json.loads(
            (server_state / "xray-server.json").read_text(encoding="utf-8")
        )
        client_config = json.loads(
            (server_state / "xray-client.json").read_text(encoding="utf-8")
        )
        server_inbound = server_config["inbounds"][0]
        client_peer = client_config["outbounds"][0]["settings"]["vnext"][0]
        client_socks = client_config["inbounds"][0]
        assert server_inbound["listen"] == _LOOPBACK
        assert server_inbound["port"] == server_port
        assert client_peer["address"] == _LOOPBACK
        assert client_peer["port"] == server_port
        assert client_socks["listen"] == _LOOPBACK
        assert client_socks["port"] == socks_port
        # Xray rejects private VLESS destinations by default. Keep this local
        # canary's server egress limited to the two loopback fixtures.
        server_config["outbounds"][0]["settings"] = {
            "targetStrategy": "ForceIPv4",
            "finalRules": [
                {
                    "action": "allow",
                    "network": "tcp",
                    "ip": [_LOOPBACK + "/32"],
                    "port": str(int(responder.server_address[1])),
                },
                {
                    "action": "allow",
                    "network": "tcp",
                    "ip": [_LOOPBACK + "/32"],
                    "port": str(int(target.server_address[1])),
                },
            ],
        }
        xray_module.validate_configs(
            {"server": server_config, "client": client_config}, binary=executable
        )
        certification._write_config(server_state / "xray-server.json", server_config)
        server_account = server_inbound["settings"]["clients"][0]
        server_reality = server_inbound["streamSettings"]["realitySettings"]
        client_reality = client_config["outbounds"][0]["streamSettings"]["realitySettings"]
        generated_secrets.update((
            server_account["id"],
            server_reality["privateKey"],
            client_reality["publicKey"],
            server_reality["shortIds"][0],
        ))

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
            raise AssertionError("import modified the exported profile")
        client_config_path = client_workdir / "state" / "xray-client.json"
        assert stat.S_IMODE(client_config_path.stat().st_mode) == 0o600

        client_up = run_cli(client_workdir, "up", "--client")
        assert client_up.returncode == 0
        _wait_port_open(socks_port)

        health_url = f"http://127.0.0.1:{responder.server_address[1]}/health"
        healthy = run_cli(client_workdir, "health", "--url", health_url)
        assert healthy.returncode == 0
        healthy_record = json.loads(healthy.stdout)
        assert healthy_record["health"] == "healthy"
        assert healthy_record["http_observed"] is True
        assert healthy_record["route"] == "configured_socks"
        assert responder.request_count == 1

        client_status = run_cli(client_workdir, "status", "--client")
        assert "status: live process (pid=" in client_status.stdout

        client_down = run_cli(client_workdir, "down", "--client")
        assert client_down.returncode == 0
        unavailable = run_cli(
            client_workdir, "health", "--url", health_url, "--timeout", "2"
        )
        assert unavailable.returncode == 1
        unavailable_record = json.loads(unavailable.stdout)
        assert unavailable_record["health"] == "unhealthy"
        assert unavailable_record["http_observed"] is False
        assert responder.request_count == 1

        client_up_again = run_cli(client_workdir, "up", "--client")
        assert client_up_again.returncode == 0
        _wait_port_open(socks_port)
        healthy_again = run_cli(client_workdir, "health", "--url", health_url)
        assert healthy_again.returncode == 0
        assert responder.request_count == 2

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
        for server_obj, thread in ((target, target_thread), (responder, responder_thread)):
            if server_obj is None:
                continue
            try:
                if thread is not None:
                    if not certification._stop_responder(server_obj, thread):
                        cleanup_failed = True
                else:
                    server_obj.server_close()
            except (OSError, RuntimeError):
                cleanup_failed = True

        profile_uri_text = ""
        try:
            if profile_path.is_file():
                profile_uri_text = profile_path.read_text(encoding="utf-8").strip()
        except OSError:
            cleanup_failed = True
        generated_secrets.add(body_secret)
        if profile_uri_text:
            generated_secrets.add(profile_uri_text)
        scan_values = tuple(generated_secrets)
        secret_scan_failed = any(
            secret in output for secret in scan_values for output in outputs
        )
        try:
            _assert_absent_from_repository(unittest.TestCase(), scan_values)
        except (AssertionError, OSError, UnicodeError):
            secret_scan_failed = True
        active_exception = sys.exc_info()[1]
        if active_exception is not None:
            if cleanup_failed:
                active_exception.add_note("loopback process/listener cleanup was incomplete")
            if secret_scan_failed:
                active_exception.add_note("generated credential scan failed; values withheld")
        elif cleanup_failed:
            raise AssertionError("loopback process/listener cleanup was incomplete")
        elif secret_scan_failed:
            raise AssertionError("generated credential scan failed; values withheld")
