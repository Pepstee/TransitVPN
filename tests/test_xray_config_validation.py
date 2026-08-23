"""Independent adversarial tests for the generated-config validation boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from transitvpn import cli
from transitvpn import xray
from transitvpn.config import XrayDeployment
from transitvpn.keygen import Keys
from transitvpn.server import build_client_config, build_server_config


class PinnedConfigValidationTests(unittest.TestCase):
    PLATFORM = ("linux", "x86_64")

    @staticmethod
    def deployment() -> XrayDeployment:
        return XrayDeployment(
            keys=Keys(
                # credential-scan: allow uuid-credential
                vless_uuid="53b78d34-f35c-4d1d-b471-97f1f0783ec3",
                # credential-scan: allow password-token
                reality_private_key="private-key-config-secret",
                reality_public_key="public-key-value",
                ss_password="unused-password-secret",  # credential-scan: allow password-token
            ),
            server="vpn.example.test",
            target="cover.example.test:443",
            server_name="cover.example.test",
            short_id="0123456789abcdef",
            target_verified=True,
        )

    def test_generated_peer_configs_are_tested_by_verified_absolute_binary(self) -> None:
        payload = b"synthetic byte-for-byte pinned xray"
        metadata = xray.XrayBinaryMetadata(
            "Xray-test.zip", hashlib.sha256(payload).hexdigest()
        )
        deployment = self.deployment()
        configs = {
            "server": build_server_config(deployment),
            "client": build_client_config(deployment),
        }

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory, "pinned-xray")
            candidate.write_bytes(payload)
            observed: list[tuple[list[str], object]] = []

            def execute(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                if argv[1:] == ["version"]:
                    return subprocess.CompletedProcess(
                        argv, 0, stdout=f"Xray {xray.XRAY_VERSION}\n", stderr=""
                    )
                self.assertEqual(argv[1:4], ["run", "-test", "-config"])
                with Path(argv[4]).open(encoding="utf-8") as handle:
                    observed.append((argv, json.load(handle)))
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            with (
                mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
                mock.patch.object(xray.shutil, "which", return_value=str(candidate)) as which,
                mock.patch.dict(xray.XRAY_BINARIES, {self.PLATFORM: metadata}, clear=True),
                mock.patch.object(xray.subprocess, "run", side_effect=execute) as run,
            ):
                identity = xray.validate_configs(configs, binary=str(candidate))

        pinned_path = str(candidate.resolve())
        which.assert_called_once_with(str(candidate))
        self.assertEqual([call.args[0][0] for call in run.call_args_list], [pinned_path] * 3)
        self.assertEqual([item[1] for item in observed], [configs["server"], configs["client"]])
        for call in run.call_args_list[1:]:
            self.assertTrue(call.kwargs["check"])
            self.assertTrue(call.kwargs["capture_output"])
            self.assertIs(call.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(identity["sha256"], metadata.executable_sha256)

    def test_stale_generated_server_and_client_shapes_are_rejected_by_pinned_xray(self) -> None:
        fixture_source = f"""#!/usr/bin/env python3
import json
import sys

if sys.argv[1:] == ["version"]:
    print("Xray {xray.XRAY_VERSION}")
    raise SystemExit(0)
if sys.argv[1:3] != ["run", "-test"] or sys.argv[3] != "-config":
    raise SystemExit(97)
with open(sys.argv[4], encoding="utf-8") as handle:
    config = json.load(handle)
streams = [item.get("streamSettings", {{}}) for group in ("inbounds", "outbounds")
           for item in config.get(group, [])]
raise SystemExit(23 if any(stream.get("network") == "tcp" for stream in streams) else 0)
"""
        deployment = self.deployment()

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory, "pinned-xray")
            candidate.write_text(fixture_source, encoding="utf-8")
            candidate.chmod(0o700)
            metadata = xray.XrayBinaryMetadata(
                "Xray-test.zip", hashlib.sha256(candidate.read_bytes()).hexdigest()
            )

            for stale_role in ("server", "client"):
                with self.subTest(stale_role=stale_role):
                    configs = {
                        "server": build_server_config(deployment),
                        "client": build_client_config(deployment),
                    }
                    stream_owner = "inbounds" if stale_role == "server" else "outbounds"
                    configs[stale_role][stream_owner][0]["streamSettings"]["network"] = "tcp"

                    with (
                        mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
                        mock.patch.dict(
                            xray.XRAY_BINARIES, {self.PLATFORM: metadata}, clear=True
                        ),
                        self.assertRaises(RuntimeError) as raised,
                    ):
                        xray.validate_configs(configs, binary=str(candidate))

                    message = str(raised.exception)
                    self.assertIn(f"{stale_role} Xray configuration", message)
                    self.assertIn("invalid, unsupported, or stale", message)

    def test_unverified_requested_binary_is_never_run_or_replaced_by_system_xray(self) -> None:
        credential = "binary-private-material-4c821"  # credential-scan: allow password-token
        with tempfile.TemporaryDirectory() as directory:
            requested = Path(directory, "requested-xray")
            requested.write_bytes(credential.encode())
            metadata = xray.XrayBinaryMetadata(
                "Xray-test.zip", hashlib.sha256(b"actual pinned bytes").hexdigest()
            )

            def lookup(name: str) -> str:
                if name == str(requested):
                    return str(requested)
                if name == "xray":
                    self.fail("validation fell back to the system Xray name")
                raise AssertionError(f"unexpected executable lookup: {name}")

            with (
                mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
                mock.patch.object(xray.shutil, "which", side_effect=lookup) as which,
                mock.patch.dict(xray.XRAY_BINARIES, {self.PLATFORM: metadata}, clear=True),
                mock.patch.object(xray.subprocess, "run") as run,
                self.assertRaises(RuntimeError) as raised,
            ):
                xray.validate_configs({"server": {}}, binary=str(requested))

        self.assertIn("unverified Xray binary", str(raised.exception))
        self.assertNotIn(credential, str(raised.exception))
        which.assert_called_once_with(str(requested))
        run.assert_not_called()

    def test_missing_requested_binary_fails_closed_without_system_fallback(self) -> None:
        requested = "/fixture/absent-pinned-xray"

        def lookup(name: str) -> None:
            self.assertEqual(name, requested)
            return None

        with (
            mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
            mock.patch.object(xray.shutil, "which", side_effect=lookup) as which,
            mock.patch.object(xray.subprocess, "run") as run,
            self.assertRaises(RuntimeError) as raised,
        ):
            xray.validate_configs({"server": {}}, binary=requested)

        self.assertIn("binary not found", str(raised.exception))
        which.assert_called_once_with(requested)
        run.assert_not_called()

    def test_non_executable_requested_binary_fails_closed_without_system_fallback(self) -> None:
        payload = b"synthetic pinned bytes without execute permission"
        metadata = xray.XrayBinaryMetadata(
            "Xray-test.zip", hashlib.sha256(payload).hexdigest()
        )
        with tempfile.TemporaryDirectory() as directory:
            requested = Path(directory, "pinned-xray")
            requested.write_bytes(payload)
            requested.chmod(0o600)

            def lookup(name: str) -> None:
                self.assertEqual(name, str(requested))
                return None

            with (
                mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
                mock.patch.object(xray.shutil, "which", side_effect=lookup) as which,
                mock.patch.dict(xray.XRAY_BINARIES, {self.PLATFORM: metadata}, clear=True),
                mock.patch.object(xray.subprocess, "run") as run,
                self.assertRaises(RuntimeError) as raised,
            ):
                xray.validate_configs({"client": {}}, binary=str(requested))

        self.assertIn("binary not found", str(raised.exception))
        which.assert_called_once_with(str(requested))
        run.assert_not_called()

    def test_rejected_config_cannot_be_accepted_as_bootstrap_artefact(self) -> None:
        fixture_source = f"""#!/usr/bin/env python3
import sys
if sys.argv[1:] == [\"version\"]:
    print(\"Xray {xray.XRAY_VERSION}\")
    raise SystemExit(0)
raise SystemExit(23)
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = root / "pinned-xray"
            candidate.write_text(fixture_source, encoding="utf-8")
            candidate.chmod(0o700)
            metadata = xray.XrayBinaryMetadata(
                "Xray-test.zip", hashlib.sha256(candidate.read_bytes()).hexdigest()
            )
            args = SimpleNamespace(
                host="vpn.example.test",
                target="cover.example.test:443",
                server_name="cover.example.test",
                target_verified=True,
                xray_binary=str(candidate),
                dry_run=False,
            )

            with (
                mock.patch.object(xray, "_platform_key", return_value=self.PLATFORM),
                mock.patch.dict(xray.XRAY_BINARIES, {self.PLATFORM: metadata}, clear=True),
                mock.patch("transitvpn.keygen.generate_keys", return_value=self.deployment().keys),
                mock.patch("transitvpn.keygen.generate_short_id", return_value="0123456789abcdef"),
                mock.patch.object(cli, "_atomic_write") as write,
            ):
                status = cli._cmd_bootstrap(args)

            self.assertEqual(status, 1)
            write.assert_not_called()

    def test_failed_validation_discards_process_output_and_config_credentials(self) -> None:
        config_secret = "privateKey=config-secret-184e"  # credential-scan: allow password-token
        stdout_secret = "uuid=stdout-secret-295f"  # credential-scan: allow password-token
        stderr_secret = "Bearer stderr-secret-3a60"  # credential-scan: allow password-token
        metadata = xray.XrayBinaryMetadata("Xray-test.zip", "a" * 64)
        failure = subprocess.CalledProcessError(
            23, ["/verified/pinned-xray", "run"], output=stdout_secret, stderr=stderr_secret
        )

        with (
            mock.patch.object(
                xray, "verify_binary", return_value=("/verified/pinned-xray", metadata)
            ) as verify,
            mock.patch.object(xray.subprocess, "run", side_effect=failure) as run,
            self.assertRaises(RuntimeError) as raised,
        ):
            xray.validate_configs({"server": {"privateKey": config_secret}}, binary="candidate")

        verify.assert_called_once_with("candidate")
        run.assert_called_once()
        message = str(raised.exception)
        self.assertIn("configuration is invalid", message)
        for secret in (config_secret, stdout_secret, stderr_secret):
            self.assertNotIn(secret, message)

    def test_malformed_configuration_fails_before_execution_without_secret_disclosure(self) -> None:
        malformed_secret = "privateKey=malformed-secret-7bd2"  # credential-scan: allow password-token
        metadata = xray.XrayBinaryMetadata("Xray-test.zip", "b" * 64)

        with (
            mock.patch.object(
                xray, "verify_binary", return_value=("/verified/pinned-xray", metadata)
            ),
            mock.patch.object(xray.subprocess, "run") as run,
            self.assertRaises(RuntimeError) as raised,
        ):
            xray.validate_configs(
                {malformed_secret: {"privateKey": malformed_secret, "bad": {object()}}}
            )

        self.assertEqual(
            str(raised.exception),
            "generated Xray configuration is not valid JSON; regenerate it",
        )
        self.assertNotIn(malformed_secret, str(raised.exception))
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
