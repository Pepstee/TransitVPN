"""Adversarial lifecycle tests for local Xray tunnel certification."""

from __future__ import annotations

from dataclasses import asdict
import unittest
from unittest import mock

from transitvpn import xray_certification as certification


class _Process:
    """Minimal process double whose final state proves teardown occurred."""

    def __init__(self) -> None:
        self.return_code: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = 0

    def wait(self, timeout: float) -> int:
        assert timeout == 2
        assert self.return_code is not None
        return self.return_code

    def kill(self) -> None:
        self.killed = True
        self.return_code = -9


class XrayCertificationFailurePathTests(unittest.TestCase):
    def _orchestration_patches(self) -> tuple[mock._patch, ...]:
        return (
            mock.patch.object(certification, "verify_binary", return_value=("/pinned/xray", "v")),
            mock.patch.object(certification, "validate_configs"),
            mock.patch.object(certification, "_ephemeral_port", side_effect=(31001, 31002)),
            mock.patch.object(certification, "_wait_ready"),
        )

    def test_client_startup_failure_stops_the_already_started_server(self) -> None:
        server = _Process()
        patches = self._orchestration_patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            mock.patch.object(
                certification,
                "_start",
                side_effect=(
                    server,
                    certification.XrayCertificationError(
                        "client Xray process could not be started"
                    ),
                ),
            ),
            self.assertRaises(certification.XrayCertificationError) as raised,
        ):
            certification.certify_local_tunnel(timeout=1.0)

        self.assertIn("client Xray process could not be started", str(raised.exception))
        self.assertTrue(server.terminated)
        self.assertIsNotNone(server.poll())

    def test_expired_shared_deadline_fails_without_probe_and_stops_both_children(self) -> None:
        server, client = _Process(), _Process()
        patches = self._orchestration_patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            mock.patch.object(certification, "_start", side_effect=(server, client)),
            mock.patch.object(certification.time, "monotonic", side_effect=(50.0, 50.2)),
            mock.patch.object(certification, "_probe") as probe,
            self.assertRaises(certification.XrayCertificationError) as raised,
        ):
            certification.certify_local_tunnel(timeout=0.1)

        self.assertIn("probe timed out", str(raised.exception))
        probe.assert_not_called()
        self.assertTrue(server.terminated)
        self.assertTrue(client.terminated)

    def test_unconfirmed_teardown_overrides_an_apparent_success(self) -> None:
        server, client = _Process(), _Process()
        patches = self._orchestration_patches()
        with (
            patches[0], patches[1], patches[2], patches[3],
            mock.patch.object(certification, "_start", side_effect=(server, client)),
            mock.patch.object(certification, "_probe", return_value=61),
            mock.patch.object(certification, "_stop", side_effect=(False, True)) as stop,
            self.assertRaises(certification.XrayCertificationError) as raised,
        ):
            certification.certify_local_tunnel(timeout=1.0)

        self.assertIn("cleanup could not be confirmed", str(raised.exception))
        self.assertEqual(stop.call_args_list, [mock.call(client), mock.call(server)])

    def test_success_evidence_schema_cannot_contain_credentials_or_endpoints(self) -> None:
        evidence = certification.XrayTunnelCertification("1.2.3", 73)

        self.assertEqual(asdict(evidence), {"version": "1.2.3", "response_bytes": 73})
        for forbidden in ("credential", "client_id", "uuid", "token", "port", "address"):
            self.assertNotIn(forbidden, repr(evidence).lower())

    def test_missing_prerequisite_fails_before_any_local_service_or_process_starts(self) -> None:
        with (
            mock.patch.object(
                certification,
                "verify_binary",
                side_effect=RuntimeError("pinned executable unavailable"),
            ),
            mock.patch.object(certification, "_Responder") as responder,
            mock.patch.object(certification, "_start") as start,
            self.assertRaises(certification.XrayCertificationError) as raised,
        ):
            certification.certify_local_tunnel(timeout=1.0)

        self.assertIn("binary verification failed", str(raised.exception))
        responder.assert_not_called()
        start.assert_not_called()


if __name__ == "__main__":
    unittest.main()
