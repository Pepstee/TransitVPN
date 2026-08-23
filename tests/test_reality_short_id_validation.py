"""Independent contract tests for REALITY deployment short IDs."""

from __future__ import annotations

import unittest

from transitvpn.config import XrayDeployment
from transitvpn.keygen import Keys


def deployment_with(short_id: str) -> XrayDeployment:
    """Build an otherwise-valid deployment, isolating short-ID validation."""
    return XrayDeployment(
        keys=Keys(
            vless_uuid="00000000-0000-4000-8000-000000000000",
            reality_private_key="private-key",
            reality_public_key="public-key",
            ss_password="password",
        ),
        server="vpn.example.com",
        target="www.example.com:443",
        server_name="www.example.com",
        short_id=short_id,
        target_verified=True,
    )


class RealityShortIdValidationTests(unittest.TestCase):
    def test_deployment_rejects_odd_length_reality_short_ids(self) -> None:
        for short_id in ("0", "abc", "0123456789abcde"):
            with self.subTest(short_id=short_id):
                with self.assertRaisesRegex(ValueError, "short_id"):
                    deployment_with(short_id)

    def test_deployment_rejects_malformed_reality_short_ids(self) -> None:
        malformed = (
            "",
            "gg",
            "0g",
            "AB",
            "ab-cd",
            " ab",
            "ab ",
            "0123456789abcdef00",
        )
        for short_id in malformed:
            with self.subTest(short_id=short_id):
                with self.assertRaisesRegex(ValueError, "short_id"):
                    deployment_with(short_id)

    def test_deployment_accepts_even_length_lowercase_hex_short_ids(self) -> None:
        for short_id in ("00", "ab12", "012345", "deadbeef", "0123456789abcdef"):
            with self.subTest(short_id=short_id):
                deployment = deployment_with(short_id)
                self.assertEqual(deployment.short_id, short_id)


if __name__ == "__main__":
    unittest.main()
