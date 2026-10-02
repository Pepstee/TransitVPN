"""Unit tests for the certify-local-tunnel CLI subcommand."""

import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from transitvpn import cli


class _FakeResult:
    def operator_record(self):
        return {
            "scope": "local-loopback",
            "external_recovery": {"status": "unprovisioned", "observed": False},
        }


class CertifyLocalTunnelParserTests(unittest.TestCase):
    def test_defaults(self):
        args = cli.build_parser().parse_args(["certify-local-tunnel"])
        self.assertEqual(args.command, "certify-local-tunnel")
        self.assertEqual(args.xray_binary, "xray")
        self.assertEqual(args.timeout, 10.0)

    def test_env_binary_default(self):
        with mock.patch.dict(cli.os.environ, {"TRANSITVPN_XRAY_BIN": "/pin/xray"}):
            args = cli.build_parser().parse_args(["certify-local-tunnel"])
        self.assertEqual(args.xray_binary, "/pin/xray")

    def test_explicit_options(self):
        args = cli.build_parser().parse_args(
            ["certify-local-tunnel", "--xray-binary", "/bin/x", "--timeout", "5.5"]
        )
        self.assertEqual(args.xray_binary, "/bin/x")
        self.assertEqual(args.timeout, 5.5)


class CertifyLocalTunnelDispatchTests(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_success_prints_operator_record_json(self):
        with mock.patch(
            "transitvpn.xray_certification.certify_local_tunnel",
            return_value=_FakeResult(),
        ) as cert:
            code, out, err = self._run(
                ["certify-local-tunnel", "--xray-binary", "/bin/x", "--timeout", "3"]
            )
        self.assertEqual(code, 0)
        self.assertEqual(err, "")
        cert.assert_called_once_with("/bin/x", timeout=3.0)
        record = json.loads(out)
        self.assertEqual(record["scope"], "local-loopback")
        self.assertEqual(
            record["external_recovery"],
            {"status": "unprovisioned", "observed": False},
        )

    def test_failure_is_fail_closed_and_concise(self):
        with mock.patch(
            "transitvpn.xray_certification.certify_local_tunnel",
            side_effect=RuntimeError("pinned Xray could not be verified"),
        ):
            code, out, err = self._run(["certify-local-tunnel"])
        self.assertNotEqual(code, 0)
        self.assertEqual(out, "")
        self.assertIn("certify-local-tunnel: error:", err)
        self.assertNotIn("Traceback", err)
        self.assertLessEqual(len(err.strip().splitlines()), 1)

    def test_invalid_timeout_rejected(self):
        code, _out, err = self._run(["certify-local-tunnel", "--timeout", "-1"])
        self.assertNotEqual(code, 0)
        self.assertNotIn("Traceback", err)


if __name__ == "__main__":
    unittest.main()
