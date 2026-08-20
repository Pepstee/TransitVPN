"""Independent adversarial tests for the generated-config validation boundary."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from transitvpn.config import XrayDeployment
from transitvpn.keygen import Keys
from transitvpn.server import build_client_config, build_server_config
from transitvpn import xray


class PinnedConfigValidationTests(unittest.TestCase):
    PLATFORM = ("linux", "x86_64")

    @staticmethod
    def deployment() -> XrayDeployment:
        return XrayDeployment(
            keys=Keys(
                vless_uuid="53b78d34-f35c-4d1d-b471-97f1f0783ec3",
                reality_private_key="private-key-config-secret",  # credential-scan: allow
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

    def test_unverified_requested_binary_is_never_run_or_replaced_by_system_xray(self) -> None:
        credential = "binary-private-material-4c821"  # credential-scan: allow
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
