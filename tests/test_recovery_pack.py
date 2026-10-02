"""Focused coverage for the private offline client recovery pack."""

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

from tests.test_xray_local_tunnel_certification import (
    _RealityTarget,
    _write_local_target_certificate,
)
from transitvpn import recovery_pack
from transitvpn import xray as xray_module
from transitvpn import xray_certification as certification
from transitvpn.config import XrayDeployment
from transitvpn.export_profile import build_profile_uri
from transitvpn.keygen import generate_keys, generate_short_id
from transitvpn.server import build_client_config

REPOSITORY = Path(__file__).resolve().parents[1]
LOOPBACK = "127.0.0.1"


def _generated_client(socks_port: int = 10808) -> dict:
    deployment = XrayDeployment(
        keys=generate_keys(),
        server="vpn.example.test",
        target="cover.example.test:443",
        server_name="cover.example.test",
        short_id=generate_short_id(),
        target_verified=True,
        port=443,
        socks_port=socks_port,
    )
    return build_client_config(deployment)


def _write_config(path: Path, config: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(config), encoding="utf-8")
    path.chmod(0o600)


def _cli(workdir: Path, *arguments: str, extra_env: dict[str, str] | None = None):
    env = {
        **os.environ,
        "PYTHONPATH": str(REPOSITORY),
    }
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-m", "transitvpn", *arguments],
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
        check=False,
    )


class TestRecoveryPack(unittest.TestCase):
    def test_actual_cli_creates_exact_private_pack_with_generic_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-unit-") as temporary:
            root = Path(temporary)
            workdir = root / "work"
            state = workdir / "state"
            state.mkdir(mode=0o700, parents=True)
            config = _generated_client()
            _write_config(state / "xray-client.json", config)
            parent = root / "private"
            parent.mkdir(mode=0o700)
            destination = parent / "recovery"

            result = _cli(
                workdir,
                "export-recovery-pack",
                "--destination",
                str(destination),
            )

            self.assertTrue(result.returncode == 0, "recovery pack CLI failed")
            self.assertTrue(
                result.stdout == "export-recovery-pack: private recovery pack created\n",
                "recovery pack CLI success output was not generic",
            )
            self.assertTrue(result.stderr == "", "recovery pack CLI wrote unexpected error output")
            self.assertTrue(
                {entry.name for entry in destination.iterdir()}
                == {"client.vless", "RECOVERY.txt"},
                "recovery pack does not contain exactly its two supported files",
            )
            profile = destination / "client.vless"
            guide = destination / "RECOVERY.txt"
            self.assertTrue(stat.S_IMODE(destination.stat().st_mode) == 0o700,
                            "pack directory is not mode 0700")
            self.assertTrue(stat.S_IMODE(profile.stat().st_mode) == 0o600,
                            "profile is not mode 0600")
            self.assertTrue(stat.S_IMODE(guide.stat().st_mode) == 0o600,
                            "guide is not mode 0600")
            self.assertTrue(
                profile.read_text(encoding="utf-8")
                == build_profile_uri(config) + "\n",
                "pack profile differs from the supported profile exporter",
            )
            guide_text = guide.read_text(encoding="utf-8")
            self.assertTrue(guide_text == recovery_pack.RECOVERY_GUIDE,
                            "pack guide differs from the static guide")
            user = config["outbounds"][0]["settings"]["vnext"][0]["users"][0]
            reality = config["outbounds"][0]["streamSettings"]["realitySettings"]
            private_values = (user["id"], reality["publicKey"], reality["shortId"])
            output = result.stdout + result.stderr
            self.assertTrue(
                all(value not in guide_text and value not in output for value in private_values),
                "profile material appeared in the guide or CLI output",
            )

    def test_existing_destination_and_symlink_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-existing-") as temporary:
            root = Path(temporary)
            workdir = root / "work"
            state = workdir / "state"
            state.mkdir(mode=0o700, parents=True)
            _write_config(state / "xray-client.json", _generated_client())
            parent = root / "private"
            parent.mkdir(mode=0o700)

            existing = parent / "existing"
            existing.mkdir(mode=0o700)
            marker = existing / "keep.txt"
            marker.write_text("existing", encoding="utf-8")
            refused_existing = _cli(
                workdir, "export-recovery-pack", "--destination", str(existing)
            )
            self.assertTrue(refused_existing.returncode == 1, "existing destination was accepted")
            self.assertTrue(marker.read_text(encoding="utf-8") == "existing",
                            "existing destination contents changed")

            target = parent / "target"
            target.mkdir(mode=0o700)
            target_marker = target / "keep.txt"
            target_marker.write_text("target", encoding="utf-8")
            link = parent / "link"
            link.symlink_to(target, target_is_directory=True)
            refused_link = _cli(
                workdir, "export-recovery-pack", "--destination", str(link)
            )
            self.assertTrue(refused_link.returncode == 1, "symlink destination was accepted")
            self.assertTrue(link.is_symlink(), "destination symlink was changed")
            self.assertTrue(target_marker.read_text(encoding="utf-8") == "target",
                            "symlink target contents changed")
            self.assertTrue(
                refused_link.stderr == "export-recovery-pack: error: private recovery pack was refused\n",
                "symlink refusal output was not generic",
            )

    def test_unsafe_parent_is_not_repaired_or_written(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-parent-") as temporary:
            root = Path(temporary)
            workdir = root / "work"
            state = workdir / "state"
            state.mkdir(mode=0o700, parents=True)
            _write_config(state / "xray-client.json", _generated_client())
            unsafe = root / "public-parent"
            unsafe.mkdir(mode=0o755)
            unsafe.chmod(0o755)
            destination = unsafe / "pack"

            result = _cli(
                workdir, "export-recovery-pack", "--destination", str(destination)
            )

            self.assertTrue(result.returncode == 1, "unsafe parent was accepted")
            self.assertTrue(not destination.exists(), "unsafe parent received a pack")
            self.assertTrue(stat.S_IMODE(unsafe.stat().st_mode) == 0o755,
                            "unsafe parent permissions were changed")
            self.assertTrue(result.stdout == "", "refusal wrote unexpected stdout")
            self.assertTrue(
                result.stderr == "export-recovery-pack: error: private recovery pack was refused\n",
                "unsafe-parent refusal output was not generic",
            )

    def test_invalid_source_removes_only_the_new_empty_pack_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-invalid-") as temporary:
            root = Path(temporary)
            workdir = root / "work"
            state = workdir / "state"
            state.mkdir(mode=0o700, parents=True)
            (state / "xray-client.json").write_text("{}", encoding="utf-8")
            (state / "xray-client.json").chmod(0o600)
            parent = root / "private"
            parent.mkdir(mode=0o700)
            destination = parent / "pack"

            result = _cli(
                workdir, "export-recovery-pack", "--destination", str(destination)
            )

            self.assertTrue(result.returncode == 1, "invalid config was accepted")
            self.assertTrue(not destination.exists(), "failed export left its empty directory")
            self.assertTrue(result.stdout == "", "invalid-config refusal wrote stdout")
            self.assertTrue(
                result.stderr == "export-recovery-pack: error: private recovery pack was refused\n",
                "invalid-config refusal output was not generic",
            )

    def test_caught_write_failure_preserves_foreign_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-foreign-") as temporary:
            root = Path(temporary)
            config_path = root / "xray-client.json"
            _write_config(config_path, _generated_client())
            parent = root / "private"
            parent.mkdir(mode=0o700)
            destination = parent / "pack"

            def leave_foreign_guide(path: Path, _identity: os.stat_result) -> None:
                path.write_text("foreign entry", encoding="utf-8")
                raise recovery_pack.RecoveryPackError()

            with (
                mock.patch.object(
                    recovery_pack, "_write_guide", side_effect=leave_foreign_guide
                ),
                self.assertRaises(recovery_pack.RecoveryPackError),
            ):
                recovery_pack.export_recovery_pack(config_path, destination)

            self.assertTrue(destination.is_dir(), "directory with foreign work was removed")
            self.assertTrue(
                (destination / "RECOVERY.txt").read_text(encoding="utf-8") == "foreign entry",
                "foreign replacement was removed or changed",
            )
            self.assertTrue(
                not (destination / "client.vless").exists(),
                "owned profile was not removed after the caught failure",
            )

    def test_guide_sync_failure_cleans_only_the_created_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="transit-pack-cleanup-") as temporary:
            root = Path(temporary)
            config_path = root / "xray-client.json"
            _write_config(config_path, _generated_client())
            parent = root / "private"
            parent.mkdir(mode=0o700)
            destination = parent / "pack"
            sentinel = parent / "keep.txt"
            sentinel.write_text("preserve", encoding="utf-8")

            with (
                mock.patch.object(recovery_pack, "_sync_directory", side_effect=OSError),
                self.assertRaises(recovery_pack.RecoveryPackError),
            ):
                recovery_pack.export_recovery_pack(config_path, destination)

            self.assertTrue(not destination.exists(), "owned failed pack was not removed")
            self.assertTrue(sentinel.read_text(encoding="utf-8") == "preserve",
                            "unrelated parent entry changed")


def _wait_port_open(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((LOOPBACK, port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.025)
    raise AssertionError("managed loopback listener did not become ready")


def _port_is_closed(port: int) -> bool:
    try:
        connection = socket.create_connection((LOOPBACK, port), timeout=0.2)
    except OSError:
        return True
    connection.close()
    return False


def test_pack_profile_imports_and_carries_loopback_http_through_restart(tmp_path: Path) -> None:
    binary = os.environ.get("TRANSITVPN_XRAY_BIN", "xray")
    executable, metadata = certification.verify_binary(binary)
    if metadata.executable_sha256 != "5200ed9b358cf380b2d9f1fe28c7e56220c0159adcd86a64592246d8257a043c":
        raise AssertionError("canary did not use the pinned Xray release")

    body_secret = secrets.token_hex(16)
    body = ("transitvpn-offline-pack:" + body_secret).encode("ascii")
    server_name = "cover.example.test"
    server_workdir = tmp_path / "server"
    client_workdir = tmp_path / "client"
    server_workdir.mkdir(mode=0o700)
    client_workdir.mkdir(mode=0o700)
    private_parent = tmp_path / "private"
    private_parent.mkdir(mode=0o700)
    pack_dir = private_parent / "recovery-pack"

    outputs: list[str] = []
    generated_secrets: list[str] = [body_secret]
    responder = None
    target = None
    responder_thread = None
    target_thread = None
    server_port: int | None = None
    socks_port: int | None = None
    target_port: int | None = None
    responder_port: int | None = None
    cleanup_failed = False

    def run_cli(workdir: Path, *arguments: str):
        result = subprocess.run(
            [sys.executable, "-m", "transitvpn", *arguments],
            cwd=workdir,
            env={
                **os.environ,
                "PYTHONPATH": str(REPOSITORY),
                "TRANSITVPN_PROXY_BIN": executable,
                "TRANSITVPN_XRAY_BIN": executable,
            },
            capture_output=True,
            text=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        outputs.extend((result.stdout, result.stderr))
        return result

    try:
        certificate_path, key_path = _write_local_target_certificate(tmp_path, server_name)
        target_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        target_tls.minimum_version = ssl.TLSVersion.TLSv1_3
        target_tls.maximum_version = ssl.TLSVersion.TLSv1_3
        target_tls.load_cert_chain(str(certificate_path), str(key_path))
        responder = certification._Responder(body)
        target = _RealityTarget(target_tls)
        responder_thread = threading.Thread(target=responder.serve_forever, daemon=True)
        target_thread = threading.Thread(target=target.serve_forever, daemon=True)
        responder_thread.start()
        target_thread.start()
        responder_port = int(responder.server_address[1])
        target_port = int(target.server_address[1])

        target_context = ssl.create_default_context(cafile=str(certificate_path))
        target_context.minimum_version = ssl.TLSVersion.TLSv1_3
        target_context.maximum_version = ssl.TLSVersion.TLSv1_3
        with (
            socket.create_connection(target.server_address, timeout=3) as raw,
            target_context.wrap_socket(raw, server_hostname=server_name) as tls,
        ):
            if tls.version() != "TLSv1.3":
                raise AssertionError("loopback REALITY cover TLS fixture was not TLS 1.3")

        used = {responder_port, target_port}

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
            "--host", LOOPBACK,
            "--listen", LOOPBACK,
            "--port", str(server_port),
            "--socks-port", str(socks_port),
            "--target", f"{LOOPBACK}:{target_port}",
            "--server-name", server_name,
            "--target-verified",
            "--xray-binary", executable,
        )
        if bootstrapped.returncode != 0:
            raise AssertionError("product bootstrap CLI failed")

        server_state = server_workdir / "state"
        server_config_path = server_state / "xray-server.json"
        server_config = json.loads(server_config_path.read_text(encoding="utf-8"))
        client_config = json.loads(
            (server_state / "xray-client.json").read_text(encoding="utf-8")
        )
        server_config["outbounds"][0]["settings"] = {
            "targetStrategy": "ForceIPv4",
            "finalRules": [
                {
                    "action": "allow", "network": "tcp",
                    "ip": [LOOPBACK + "/32"], "port": str(responder_port),
                },
                {
                    "action": "allow", "network": "tcp",
                    "ip": [LOOPBACK + "/32"], "port": str(target_port),
                },
            ],
        }
        xray_module.validate_configs(
            {"server": server_config, "client": client_config}, binary=executable
        )
        certification._write_config(server_config_path, server_config)
        server_account = server_config["inbounds"][0]["settings"]["clients"][0]
        reality = server_config["inbounds"][0]["streamSettings"]["realitySettings"]
        generated_secrets.extend((
            server_account["id"],
            reality["privateKey"],
            reality["shortIds"][0],
            client_config["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"],
        ))

        exported = run_cli(
            server_workdir,
            "export-recovery-pack",
            "--destination", str(pack_dir),
        )
        if exported.returncode != 0:
            raise AssertionError("product recovery-pack CLI failed")
        if exported.stdout != "export-recovery-pack: private recovery pack created\n":
            raise AssertionError("product recovery-pack CLI output was not generic")
        if exported.stderr:
            raise AssertionError("product recovery-pack CLI wrote unexpected diagnostics")
        if {entry.name for entry in pack_dir.iterdir()} != {"client.vless", "RECOVERY.txt"}:
            raise AssertionError("exported pack does not contain exactly its two files")
        profile_path = pack_dir / "client.vless"
        guide_path = pack_dir / "RECOVERY.txt"
        if stat.S_IMODE(pack_dir.stat().st_mode) != 0o700:
            raise AssertionError("exported pack directory is not private")
        if stat.S_IMODE(profile_path.stat().st_mode) != 0o600:
            raise AssertionError("exported profile is not private")
        if stat.S_IMODE(guide_path.stat().st_mode) != 0o600:
            raise AssertionError("exported guide is not private")
        guide_text = guide_path.read_text(encoding="utf-8")
        if any(value in guide_text or value in exported.stdout + exported.stderr
               for value in generated_secrets):
            raise AssertionError("generated profile material appeared in guide or CLI output")

        server_up = run_cli(server_workdir, "up")
        if server_up.returncode != 0:
            raise AssertionError("product server start failed")
        _wait_port_open(server_port)
        imported = run_cli(
            client_workdir,
            "import-profile",
            "--input", str(profile_path),
            "--socks-port", str(socks_port),
            "--xray-binary", executable,
        )
        if imported.returncode != 0:
            raise AssertionError("product import CLI rejected the packaged profile")
        client_up = run_cli(client_workdir, "up", "--client")
        if client_up.returncode != 0:
            raise AssertionError("product client start failed")
        _wait_port_open(socks_port)

        health_url = f"http://{LOOPBACK}:{responder_port}/health"
        healthy = run_cli(client_workdir, "health", "--url", health_url)
        if healthy.returncode != 0:
            raise AssertionError("packaged client did not carry the loopback HTTP request")
        healthy_record = json.loads(healthy.stdout)
        if healthy_record.get("health") != "healthy" or healthy_record.get("http_observed") is not True:
            raise AssertionError("packaged profile health observation was incomplete")
        if responder.request_count != 1:
            raise AssertionError("expected one real loopback HTTP request through Xray")

        server_down = run_cli(server_workdir, "down")
        if server_down.returncode != 0:
            raise AssertionError("product server stop failed")
        unhealthy = run_cli(client_workdir, "health", "--url", health_url)
        if unhealthy.returncode != 1:
            raise AssertionError("health did not fail while the server was stopped")
        unhealthy_record = json.loads(unhealthy.stdout)
        if unhealthy_record.get("health") != "unhealthy" or unhealthy_record.get("http_observed") is not False:
            raise AssertionError("stopped-server health result did not report an HTTP failure")
        if responder.request_count != 1:
            raise AssertionError("stopped-server request unexpectedly reached the HTTP responder")

        server_restarted = run_cli(server_workdir, "up")
        if server_restarted.returncode != 0:
            raise AssertionError("product server restart failed")
        _wait_port_open(server_port)
        recovered = run_cli(client_workdir, "health", "--url", health_url)
        if recovered.returncode != 0:
            raise AssertionError("packaged client did not recover after server restart")
        recovered_record = json.loads(recovered.stdout)
        if recovered_record.get("health") != "healthy" or responder.request_count != 2:
            raise AssertionError("post-restart HTTP request was not observed")
    finally:
        for workdir in (client_workdir, server_workdir):
            if workdir.exists():
                for command in (("down", "--client"), ("down",)):
                    try:
                        result = run_cli(workdir, *command)
                    except (OSError, subprocess.SubprocessError):
                        cleanup_failed = True
                        continue
                    if result.returncode not in (0, 1):
                        cleanup_failed = True
        if responder is not None:
            responder.shutdown()
            responder.server_close()
        if target is not None:
            target.shutdown()
            target.server_close()
        for thread in (responder_thread, target_thread):
            if thread is not None:
                thread.join(timeout=5)
                if thread.is_alive():
                    cleanup_failed = True
        for port in (server_port, socks_port):
            if port is not None and not _port_is_closed(port):
                cleanup_failed = True
        if any(value in output for value in generated_secrets for output in outputs):
            raise AssertionError("generated credentials appeared in CLI output")
        if cleanup_failed:
            raise AssertionError("private loopback canary cleanup was incomplete")
