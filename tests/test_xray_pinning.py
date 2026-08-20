"""Adversarial tests for rejection of untrusted Xray executables."""

from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from transitvpn import xray


class XrayPinningFailureTests(unittest.TestCase):
    _PLATFORM = ("linux", "x86_64")

    def _metadata_for(self, payload: bytes) -> xray.XrayBinaryMetadata:
        return xray.XrayBinaryMetadata(
            asset="Xray-test.zip",
            executable_sha256=hashlib.sha256(payload).hexdigest(),
        )

    def test_checksum_mismatch_rejects_without_execution_or_secret_disclosure(self) -> None:
        credential = "password=checksum-secret-7d821"  # credential-scan: allow password-token
        payload = f"untrusted binary containing {credential}".encode()

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory, "xray")
            candidate.write_bytes(payload)
            wrong_metadata = self._metadata_for(b"the pinned executable")

            with (
                mock.patch.object(xray, "_platform_key", return_value=self._PLATFORM),
                mock.patch.object(xray.shutil, "which", return_value=str(candidate)),
                mock.patch.dict(xray.XRAY_BINARIES, {self._PLATFORM: wrong_metadata}, clear=True),
                mock.patch.object(xray.subprocess, "run") as run,
                self.assertRaises(RuntimeError) as raised,
            ):
                xray.verify_binary()

        message = str(raised.exception)
        self.assertIn("unverified Xray binary", message)
        self.assertNotIn(credential, message)
        self.assertNotIn(payload.decode(), message)
        run.assert_not_called()

    def test_version_mismatch_rejects_without_captured_output_or_secret_disclosure(self) -> None:
        payload = b"byte-for-byte pinned test executable"
        stdout_secret = "token=stdout-secret-a91f"  # credential-scan: allow password-token
        stderr_secret = "Authorization: Bearer stderr-secret-b62e"  # credential-scan: allow password-token
        reported_version = "Xray 0.0.0"

        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory, "xray")
            candidate.write_bytes(payload)
            metadata = self._metadata_for(payload)
            completed = subprocess.CompletedProcess(
                [str(candidate), "version"],
                0,
                stdout=f"{reported_version} {stdout_secret}\n",
                stderr=stderr_secret,
            )

            with (
                mock.patch.object(xray, "_platform_key", return_value=self._PLATFORM),
                mock.patch.object(xray.shutil, "which", return_value=str(candidate)),
                mock.patch.dict(xray.XRAY_BINARIES, {self._PLATFORM: metadata}, clear=True),
                mock.patch.object(xray.subprocess, "run", return_value=completed) as run,
                self.assertRaises(RuntimeError) as raised,
            ):
                xray.verify_binary()

        message = str(raised.exception)
        self.assertIn("Xray version mismatch", message)
        for sensitive in (reported_version, stdout_secret, stderr_secret):
            self.assertNotIn(sensitive, message)
        run.assert_called_once_with(
            [str(candidate.resolve()), "version"],
            check=True,
            text=True,
            capture_output=True,
            timeout=10,
        )


if __name__ == "__main__":
    unittest.main()
