"""Independent adversarial coverage for the local Xray tunnel certificate."""

from __future__ import annotations

import json
from pathlib import Path
import secrets
import socket
import tempfile
import unittest
import uuid
from unittest import mock

from transitvpn import xray
from transitvpn import xray_certification as certification


REPOSITORY = Path(__file__).resolve().parents[1]


def _assert_absent_from_repository(test: unittest.TestCase, values: tuple[str, ...]) -> None:
    needles = tuple(value.encode("utf-8") for value in values)
    for candidate in REPOSITORY.rglob("*"):
        if ".git" in candidate.parts or not candidate.is_file():
            continue
        try:
            contents = candidate.read_bytes()
        except OSError:
            continue
        for value, needle in zip(values, needles):
            test.assertNotIn(needle, contents, f"temporary secret leaked to {candidate}: {value}")


class LocalXrayTunnelCertificationTests(unittest.TestCase):
    def test_real_pinned_xray_transfers_application_bytes_when_available(self) -> None:
        try:
            executable, _ = xray.verify_binary()
        except RuntimeError as exc:
            self.skipTest(f"pinned Xray binary is unavailable: {exc}")

        body_secret = secrets.token_hex(24)
        client_secret = uuid.uuid4()
        with (
            mock.patch.object(certification.secrets, "token_hex", return_value=body_secret),
            mock.patch.object(certification.uuid, "uuid4", return_value=client_secret),
        ):
            result = certification.certify_local_tunnel(executable, timeout=10.0)

        self.assertEqual(result.version, xray.XRAY_VERSION)
        self.assertEqual(
            result.response_bytes,
            len("transitvpn-xray-certification:" + body_secret),
        )
        _assert_absent_from_repository(self, (body_secret, str(client_secret)))

    def test_missing_and_invalid_binaries_cannot_report_success(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "does-not-exist"
            invalid = root / "xray"
            invalid.write_bytes(b"not the pinned Xray executable")
            invalid.chmod(0o700)

            for candidate in (missing, invalid):
                with self.subTest(candidate=candidate.name):
                    with self.assertRaises(certification.XrayCertificationError) as raised:
                        certification.certify_local_tunnel(str(candidate), timeout=0.5)
                    self.assertIn("binary verification failed", str(raised.exception))

    def test_unavailable_socks_endpoint_is_a_closed_failure(self) -> None:
        expected = b"must never be reported as transferred"
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unavailable:
            unavailable.bind(("127.0.0.1", 0))
            port = int(unavailable.getsockname()[1])
            with self.assertRaises(certification.XrayCertificationError) as raised:
                certification._probe(port, 9, expected, timeout=0.2)

        self.assertIn("tunnel probe failed", str(raised.exception))

    def test_generated_credentials_exist_only_in_a_cleaned_temporary_fixture(self) -> None:
        client_secret = str(uuid.uuid4())
        response_secret = secrets.token_hex(24)
        with tempfile.TemporaryDirectory(prefix="xray-certification-test-") as directory:
            temporary_root = Path(directory)
            config_path = temporary_root / "server.json"
            configs = certification._configs(23451, 23452, client_secret)
            certification._write_config(config_path, configs["server"])
            serialized = config_path.read_text(encoding="utf-8")
            self.assertEqual(json.loads(serialized), configs["server"])
            self.assertIn(client_secret, serialized)
            transient_payload = temporary_root / "response.secret"
            transient_payload.write_text(response_secret, encoding="utf-8")

        self.assertFalse(temporary_root.exists())
        _assert_absent_from_repository(self, (client_secret, response_secret))


if __name__ == "__main__":
    unittest.main()
