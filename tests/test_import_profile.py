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


    def test_explicit_replacement_updates_only_a_stopped_private_config(self) -> None:
        _old_config, old_uri, _old_keys = _generated_pair()
        _new_config, new_uri, _new_keys = _generated_pair()
        with tempfile.TemporaryDirectory(prefix="transitvpn-import-replace-") as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            old_profile = private / "old.vless"
            new_profile = private / "new.vless"
            old_profile.write_text(old_uri + "\n", encoding="utf-8")
            new_profile.write_text(new_uri + "\n", encoding="utf-8")
            old_profile.chmod(0o600)
            new_profile.chmod(0o600)
            output = root / "state" / "xray-client.json"
            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                return_value={"version": "test", "sha256": "0" * 64},
            ):
                import_profile(old_profile, output)
                previous = output.read_bytes()
                import_profile(new_profile, output, replace_existing=True)
            self.assertTrue(
                output.read_bytes() != previous,
                "explicit profile replacement did not update the config",
            )
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(
                sorted(path.name for path in output.parent.iterdir()),
                ["xray-client.json"],
            )

    def test_replacement_validation_and_staging_failures_preserve_old_bytes(self) -> None:
        _old_config, old_uri, _old_keys = _generated_pair()
        _new_config, new_uri, _new_keys = _generated_pair()
        with tempfile.TemporaryDirectory(prefix="transitvpn-import-replace-fail-") as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            old_profile = private / "old.vless"
            new_profile = private / "new.vless"
            old_profile.write_text(old_uri + "\n", encoding="utf-8")
            new_profile.write_text(new_uri + "\n", encoding="utf-8")
            old_profile.chmod(0o600)
            new_profile.chmod(0o600)
            output = root / "state" / "xray-client.json"
            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                return_value={"version": "test", "sha256": "0" * 64},
            ):
                import_profile(old_profile, output)
            previous = output.read_bytes()

            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                side_effect=RuntimeError("invalid"),
            ), self.assertRaises(ProfileImportError):
                import_profile(new_profile, output, replace_existing=True)
            self.assertTrue(
                output.read_bytes() == previous,
                "invalid pinned config validation changed the prior config",
            )

            with (
                mock.patch(
                    "transitvpn.import_profile.validate_configs",
                    return_value={"version": "test", "sha256": "0" * 64},
                ),
                mock.patch(
                    "transitvpn.import_profile.os.write",
                    side_effect=OSError("staging write failed"),
                ),
                self.assertRaises(ProfileImportError),
            ):
                import_profile(new_profile, output, replace_existing=True)
            self.assertTrue(
                output.read_bytes() == previous,
                "failed replacement staging changed the prior config",
            )
            self.assertEqual(
                sorted(path.name for path in output.parent.iterdir()),
                ["xray-client.json"],
            )

    def test_replacement_refuses_lifecycle_entries_and_unsafe_destinations(self) -> None:
        _old_config, old_uri, _old_keys = _generated_pair()
        _new_config, new_uri, _new_keys = _generated_pair()
        with tempfile.TemporaryDirectory(prefix="transitvpn-import-replace-safe-") as directory:
            root = Path(directory)
            private = root / "private"
            private.mkdir(mode=0o700)
            old_profile = private / "old.vless"
            new_profile = private / "new.vless"
            old_profile.write_text(old_uri + "\n", encoding="utf-8")
            new_profile.write_text(new_uri + "\n", encoding="utf-8")
            old_profile.chmod(0o600)
            new_profile.chmod(0o600)
            output = root / "state" / "xray-client.json"
            with mock.patch(
                "transitvpn.import_profile.validate_configs",
                return_value={"version": "test", "sha256": "0" * 64},
            ):
                import_profile(old_profile, output)
                previous = output.read_bytes()
                pid_record = output.parent / "tunnel-client.pid"
                pid_record.write_text("not a valid pid record\n", encoding="ascii")
                with self.assertRaises(ProfileImportError):
                    import_profile(new_profile, output, replace_existing=True)
                self.assertTrue(
                    output.read_bytes() == previous,
                    "lifecycle-record refusal changed the prior config",
                )
                self.assertEqual(
                    pid_record.read_text(encoding="ascii"),
                    "not a valid pid record\n",
                )
                pid_record.unlink()

                pid_record.symlink_to(output.parent / "missing-record-target")
                with self.assertRaises(ProfileImportError):
                    import_profile(new_profile, output, replace_existing=True)
                self.assertTrue(
                    output.read_bytes() == previous,
                    "dangling lifecycle symlink refusal changed the prior config",
                )
                self.assertTrue(pid_record.is_symlink())
                pid_record.unlink()

                output.chmod(0o644)
                with self.assertRaises(ProfileImportError):
                    import_profile(new_profile, output, replace_existing=True)
                self.assertTrue(
                    output.read_bytes() == previous,
                    "unsafe-mode refusal changed the prior config",
                )
                output.chmod(0o600)
                os.link(output, output.parent / "extra-link")
                with self.assertRaises(ProfileImportError):
                    import_profile(new_profile, output, replace_existing=True)
                self.assertTrue(
                    output.read_bytes() == previous,
                    "multiple-link refusal changed the prior config",
                )
                (output.parent / "extra-link").unlink()
                preserved = output.with_name("preserved-client.json")
                output.rename(preserved)
                output.symlink_to(preserved)
                with self.assertRaises(ProfileImportError):
                    import_profile(new_profile, output, replace_existing=True)
                self.assertTrue(output.is_symlink())
                self.assertTrue(
                    preserved.read_bytes() == previous,
                    "symlink destination refusal changed the original config",
                )


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
    assert args.replace_existing is False
    replace_args = cli.build_parser().parse_args(
        ["import-profile", "--input", "p.vless", "--replace"]
    )
    assert replace_args.replace_existing is True
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
    replaced = _run_cli(
        ["import-profile", "--input", str(profile), "--replace"], tmp_path
    )
    assert replaced.returncode == 0
    assert replaced.stdout == "import-profile: client profile imported and validated\n"
    assert replaced.stderr == ""


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
    import signal

    from transitvpn import xray as xray_module
    from transitvpn import xray_certification as certification
    from transitvpn.tunnel import _identity_matches, _read_record, get_status

    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    try:
        executable, _ = certification.verify_binary(binary)
    except RuntimeError:
        raise AssertionError("pinned Xray binary is unavailable for the service canary") from None

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
    service_unit = f"transitvpn-recovery-{os.getpid()}-{secrets.token_hex(6)}.service"
    service_unit_attempted = False

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

    def run_manager(*arguments: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(arguments),
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        outputs.extend((result.stdout, result.stderr))
        return result

    def wait_service_child(previous_pid: int | None = None, timeout: float = 20.0) -> int:
        deadline = time.monotonic() + timeout
        pid_file = server_workdir / "state" / "tunnel.pid"
        while time.monotonic() < deadline:
            record, _raw = _read_record(pid_file)
            if (
                record is not None
                and record["pid"] != previous_pid
                and get_status(str(server_workdir / "state")) == (True, record["pid"])
            ):
                return record["pid"]
            time.sleep(0.05)
        raise AssertionError("transient service did not expose a verified Xray child")

    profile_path = server_workdir / "private-export" / "client.vless"
    refreshed_profile_path = server_workdir / "private-export" / "client-refreshed.vless"
    profile_paths = [profile_path, refreshed_profile_path]
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
        imported_client_config = client_config_path.read_bytes()

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

        client_down_for_backup = run_cli(client_workdir, "down", "--client")
        assert client_down_for_backup.returncode == 0
        server_down_for_backup = run_cli(server_workdir, "down")
        assert server_down_for_backup.returncode == 0
        server_state = server_workdir / "state"
        server_config_paths = {
            name: server_state / name
            for name in ("xray-server.json", "xray-client.json")
        }
        original_server_configs = {
            name: path.read_bytes() for name, path in server_config_paths.items()
        }
        backup_parent = tmp_path / "private-backups"
        backup_parent.mkdir(mode=0o700)
        backup_path = backup_parent / "recovery"
        backed_up = run_cli(
            server_workdir,
            "config-backup",
            "--destination",
            str(backup_path),
        )
        assert backed_up.returncode == 0
        assert backed_up.stdout == "config-backup: private configuration backup created\n"
        assert backed_up.stderr == ""
        assert stat.S_IMODE(backup_path.stat().st_mode) == 0o700
        assert sorted(path.name for path in backup_path.iterdir()) == [
            "xray-client.json",
            "xray-server.json",
        ]
        for name, original in original_server_configs.items():
            backup_file = backup_path / name
            backup_info = backup_file.stat()
            assert stat.S_ISREG(backup_info.st_mode)
            assert stat.S_IMODE(backup_info.st_mode) == 0o600
            assert backup_info.st_nlink == 1
            if backup_file.read_bytes() != original:
                raise AssertionError("private backup did not preserve configuration bytes")

        for path in server_config_paths.values():
            path.unlink()
        missing_server_up = run_cli(server_workdir, "up")
        assert missing_server_up.returncode == 1
        assert not (server_state / "tunnel.pid").exists()

        client_up_for_loss_check = run_cli(client_workdir, "up", "--client")
        assert client_up_for_loss_check.returncode == 0
        _wait_port_open(socks_port)
        missing_config_health = run_cli(
            client_workdir, "health", "--url", health_url, "--timeout", "2"
        )
        assert missing_config_health.returncode == 1
        missing_config_health_record = json.loads(missing_config_health.stdout)
        assert missing_config_health_record["health"] == "unhealthy"
        assert missing_config_health_record["http_observed"] is False
        assert responder.request_count == 1

        client_down_before_restore = run_cli(client_workdir, "down", "--client")
        assert client_down_before_restore.returncode == 0
        restored = run_cli(
            server_workdir,
            "config-restore",
            "--source",
            str(backup_path),
            "--xray-binary",
            executable,
        )
        assert restored.returncode == 0
        assert restored.stdout == (
            "config-restore: trusted configuration backup restored and validated\n"
        )
        assert restored.stderr == ""
        for name, original in original_server_configs.items():
            restored_file = server_config_paths[name]
            restored_info = restored_file.stat()
            assert stat.S_ISREG(restored_info.st_mode)
            assert stat.S_IMODE(restored_info.st_mode) == 0o600
            assert restored_info.st_nlink == 1
            if restored_file.read_bytes() != original:
                raise AssertionError("restored configuration did not match trusted backup")

        server_up_again = run_cli(server_workdir, "up")
        assert server_up_again.returncode == 0
        _wait_port_open(server_port)
        client_still_down = run_cli(
            client_workdir, "health", "--url", health_url, "--timeout", "2"
        )
        assert client_still_down.returncode == 1
        client_still_down_record = json.loads(client_still_down.stdout)
        assert client_still_down_record["health"] == "unhealthy"
        assert client_still_down_record["http_observed"] is False
        assert responder.request_count == 1

        client_up_again = run_cli(client_workdir, "up", "--client")
        assert client_up_again.returncode == 0
        _wait_port_open(socks_port)
        if client_config_path.read_bytes() != imported_client_config:
            raise AssertionError("restore changed the imported client configuration")
        healthy_again = run_cli(client_workdir, "health", "--url", health_url)
        assert healthy_again.returncode == 0
        healthy_again_record = json.loads(healthy_again.stdout)
        assert healthy_again_record["health"] == "healthy"
        assert healthy_again_record["http_observed"] is True
        assert healthy_again_record["route"] == "configured_socks"
        assert responder.request_count == 2

        client_down_for_refresh = run_cli(client_workdir, "down", "--client")
        assert client_down_for_refresh.returncode == 0
        server_down_for_refresh = run_cli(server_workdir, "down")
        assert server_down_for_refresh.returncode == 0
        assert _port_is_closed(server_port)

        refreshed_bootstrap = run_cli(
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
        assert refreshed_bootstrap.returncode == 0
        refreshed_server_config = json.loads(
            (server_state / "xray-server.json").read_text(encoding="utf-8")
        )
        refreshed_client_config = json.loads(
            (server_state / "xray-client.json").read_text(encoding="utf-8")
        )
        refreshed_server_config["outbounds"][0]["settings"] = {
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
            {
                "server": refreshed_server_config,
                "client": refreshed_client_config,
            },
            binary=executable,
        )
        certification._write_config(
            server_state / "xray-server.json", refreshed_server_config
        )
        refreshed_account = refreshed_server_config["inbounds"][0]["settings"][
            "clients"
        ][0]
        refreshed_reality = refreshed_server_config["inbounds"][0][
            "streamSettings"
        ]["realitySettings"]
        refreshed_client_reality = refreshed_client_config["outbounds"][0][
            "streamSettings"
        ]["realitySettings"]
        generated_secrets.update(
            (
                refreshed_account["id"],
                refreshed_reality["privateKey"],
                refreshed_client_reality["publicKey"],
                refreshed_reality["shortIds"][0],
            )
        )

        refreshed_server_up = run_cli(server_workdir, "up")
        assert refreshed_server_up.returncode == 0
        _wait_port_open(server_port)
        refreshed_export = run_cli(
            server_workdir,
            "export-profile",
            "--output",
            str(refreshed_profile_path),
        )
        assert refreshed_export.returncode == 0
        if refreshed_profile_path.read_bytes() == profile_before:
            raise AssertionError(
                "fresh server credentials did not produce a different client profile"
            )

        old_client_up = run_cli(client_workdir, "up", "--client")
        assert old_client_up.returncode == 0
        _wait_port_open(socks_port)
        old_profile_failure = run_cli(
            client_workdir, "health", "--url", health_url, "--timeout", "2"
        )
        assert old_profile_failure.returncode == 1
        old_profile_record = json.loads(old_profile_failure.stdout)
        assert old_profile_record["health"] == "unhealthy"
        assert old_profile_record["http_observed"] is False
        assert responder.request_count == 2

        client_down_before_replace = run_cli(client_workdir, "down", "--client")
        assert client_down_before_replace.returncode == 0
        assert not (
            client_workdir / "state" / "tunnel-client.pid"
        ).exists()
        prior_client_config = client_config_path.read_bytes()
        refreshed_import = run_cli(
            client_workdir,
            "import-profile",
            "--input",
            str(refreshed_profile_path),
            "--socks-port",
            str(socks_port),
            "--replace",
        )
        assert refreshed_import.returncode == 0
        assert refreshed_import.stdout == (
            "import-profile: client profile imported and validated\n"
        )
        assert refreshed_import.stderr == ""
        if client_config_path.read_bytes() == prior_client_config:
            raise AssertionError(
                "explicit profile replacement did not update the stopped client config"
            )
        assert stat.S_IMODE(client_config_path.stat().st_mode) == 0o600

        refreshed_client_up = run_cli(client_workdir, "up", "--client")
        assert refreshed_client_up.returncode == 0
        _wait_port_open(socks_port)
        refreshed_health = run_cli(
            client_workdir, "health", "--url", health_url
        )
        assert refreshed_health.returncode == 0
        refreshed_health_record = json.loads(refreshed_health.stdout)
        assert refreshed_health_record["health"] == "healthy"
        assert refreshed_health_record["http_observed"] is True
        assert refreshed_health_record["route"] == "configured_socks"
        assert responder.request_count == 3

        service_client_config = client_config_path.read_bytes()
        manual_server_down = run_cli(server_workdir, "down")
        assert manual_server_down.returncode == 0
        assert get_status(str(server_workdir / "state")) == (False, None)
        assert _port_is_closed(server_port)

        service_unit_attempted = True
        service_start = run_manager(
            "systemd-run",
            "--user",
            f"--unit={service_unit}",
            "--collect",
            "--working-directory",
            str(server_workdir),
            "--property=RuntimeMaxSec=60s",
            "--property=Restart=on-failure",
            "--property=RestartSec=1s",
            "--property=StartLimitIntervalSec=30s",
            "--property=StartLimitBurst=5",
            "--property=StandardOutput=null",
            "--property=StandardError=null",
            f"--setenv=PYTHONPATH={REPOSITORY}",
            f"--setenv=TRANSITVPN_PROXY_BIN={executable}",
            f"--setenv=TRANSITVPN_XRAY_BIN={executable}",
            sys.executable,
            "-m",
            "transitvpn",
            "serve",
        )
        assert service_start.returncode == 0, "transient user service could not be started"
        first_service_pid = wait_service_child()
        assert run_manager("systemctl", "--user", "is-active", service_unit).returncode == 0
        _wait_port_open(server_port)
        service_health = run_cli(client_workdir, "health", "--url", health_url)
        assert service_health.returncode == 0
        service_health_record = json.loads(service_health.stdout)
        assert service_health_record["health"] == "healthy"
        assert service_health_record["http_observed"] is True
        assert service_health_record["route"] == "configured_socks"
        assert responder.request_count == 4

        service_record, _service_record_bytes = _read_record(
            server_workdir / "state" / "tunnel.pid"
        )
        if service_record is None or service_record["pid"] != first_service_pid:
            raise AssertionError("service child ownership record changed before crash test")
        service_pidfd = os.pidfd_open(first_service_pid, 0)
        try:
            if not _identity_matches(service_record, service_pidfd):
                raise AssertionError("service child identity could not be verified")
            signal.pidfd_send_signal(service_pidfd, signal.SIGKILL)
        finally:
            os.close(service_pidfd)

        recovered_service_pid = wait_service_child(previous_pid=first_service_pid)
        assert recovered_service_pid != first_service_pid
        assert run_manager("systemctl", "--user", "is-active", service_unit).returncode == 0
        _wait_port_open(server_port)
        recovered_service_health = run_cli(
            client_workdir, "health", "--url", health_url
        )
        assert recovered_service_health.returncode == 0
        recovered_service_record = json.loads(recovered_service_health.stdout)
        assert recovered_service_record["health"] == "healthy"
        assert recovered_service_record["http_observed"] is True
        assert recovered_service_record["route"] == "configured_socks"
        assert responder.request_count == 5
        if client_config_path.read_bytes() != service_client_config:
            raise AssertionError("service recovery changed the imported client config")

        service_stop = run_manager("systemctl", "--user", "stop", service_unit)
        assert service_stop.returncode == 0, "transient service stop failed"
        service_unit_attempted = False
        time.sleep(1.25)
        stopped_health = run_cli(client_workdir, "health", "--url", health_url)
        assert stopped_health.returncode == 1
        stopped_health_record = json.loads(stopped_health.stdout)
        assert stopped_health_record["health"] == "unhealthy"
        assert stopped_health_record["http_observed"] is False
        assert responder.request_count == 5
        assert get_status(str(server_workdir / "state")) == (False, None)
        assert not (server_workdir / "state" / "tunnel.pid").exists()
        assert _port_is_closed(server_port)
        assert run_manager("systemctl", "--user", "is-active", service_unit).returncode != 0

        final_client_down = run_cli(client_workdir, "down", "--client")
        assert final_client_down.returncode == 0
        final_server_down = run_cli(server_workdir, "down")
        assert final_server_down.returncode == 0
        assert get_status(
            str(client_workdir / "state"), pid_name="tunnel-client.pid"
        ) == (False, None)
        assert get_status(str(server_workdir / "state")) == (False, None)
    finally:
        if service_unit_attempted:
            try:
                unit_state = run_manager(
                    "systemctl", "--user", "is-active", service_unit
                )
                if (
                    unit_state.returncode == 0
                    or unit_state.stdout.strip() in {"activating", "deactivating"}
                ) and run_manager(
                    "systemctl", "--user", "stop", service_unit
                ).returncode != 0:
                    cleanup_failed = True
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
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

        for candidate_profile in profile_paths:
            try:
                if candidate_profile.is_file():
                    profile_uri_text = candidate_profile.read_text(
                        encoding="utf-8"
                    ).strip()
                    if profile_uri_text:
                        generated_secrets.add(profile_uri_text)
            except OSError:
                cleanup_failed = True
        generated_secrets.add(body_secret)
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
