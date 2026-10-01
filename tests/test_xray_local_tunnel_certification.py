"""Independent adversarial coverage for the local Xray tunnel certificate."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import secrets
import ssl
import socket
import socketserver
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from transitvpn import xray
from transitvpn import xray_certification as certification
from transitvpn.config import XrayDeployment
from transitvpn.keygen import generate_keys, generate_short_id
from transitvpn.server import build_client_config, build_server_config


REPOSITORY = Path(__file__).resolve().parents[1]
_LOOPBACK = "127.0.0.1"


class _RealityTarget(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, tls_context: ssl.SSLContext) -> None:
        self.tls_context = tls_context
        self._connection_count = 0
        self._connection_lock = threading.Lock()
        super().__init__((_LOOPBACK, 0), _RealityTargetHandler)

    @property
    def connection_count(self) -> int:
        with self._connection_lock:
            return self._connection_count

    def record_connection(self) -> None:
        with self._connection_lock:
            self._connection_count += 1


class _RealityTargetHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.server.record_connection()  # type: ignore[attr-defined]
        try:
            with self.server.tls_context.wrap_socket(  # type: ignore[attr-defined]
                self.request, server_side=True
            ) as connection:
                while connection.recv(4096):
                    pass
        except (OSError, ssl.SSLError):
            return


def _write_local_target_certificate(
    directory: Path, server_name: str
) -> tuple[Path, Path]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)])
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(server_name)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    certificate_path = directory / "reality-target-cert.pem"
    key_path = directory / "reality-target-key.pem"
    certificate_path.write_bytes(
        certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    certificate_path.chmod(0o600)
    key_path.chmod(0o600)
    return certificate_path, key_path


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
    def test_private_destination_exception_is_limited_to_the_responder(self) -> None:
        configs = certification._configs(23451, 23452, str(uuid.uuid4()), responder_port=23453)
        settings = configs["server"]["outbounds"][0]["settings"]
        self.assertEqual(settings["targetStrategy"], "ForceIPv4")
        self.assertEqual(settings["finalRules"], [{
            "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": "23453",
        }])
        self.assertNotIn("settings", certification._configs(23451, 23452, str(uuid.uuid4()))["server"]["outbounds"][0])

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

    def test_wrong_vless_credential_never_reaches_http_responder(self) -> None:
        try:
            executable, _ = xray.verify_binary()
        except RuntimeError as exc:
            self.skipTest(f"pinned Xray binary is unavailable: {exc}")

        body_secret = secrets.token_hex(24)
        server_credential = uuid.uuid4()
        wrong_client_credential = uuid.uuid4()
        self.assertNotEqual(server_credential, wrong_client_credential)
        responders: list[certification._Responder] = []
        responder_type = certification._Responder

        def capture_responder(*args: object, **kwargs: object) -> certification._Responder:
            responder = responder_type(*args, **kwargs)
            responders.append(responder)
            return responder

        with (
            mock.patch.object(certification.secrets, "token_hex", return_value=body_secret),
            mock.patch.object(
                certification.uuid,
                "uuid4",
                side_effect=[server_credential, wrong_client_credential],
            ),
            mock.patch.object(certification, "_Responder", side_effect=capture_responder),
        ):
            with self.assertRaises(certification.XrayCertificationError):
                certification.certify_local_tunnel(
                    executable, timeout=10.0, credential_mismatch=True
                )

        self.assertEqual(len(responders), 1)
        self.assertEqual(responders[0].request_count, 0)
        _assert_absent_from_repository(
            self,
            (body_secret, str(server_credential), str(wrong_client_credential)),
        )

    def test_wrong_reality_short_id_uses_only_loopback_fallback(self) -> None:
        self._assert_wrong_reality_mismatch_uses_only_loopback_fallback("short-id")

    def test_wrong_reality_public_key_uses_only_loopback_fallback(self) -> None:
        self._assert_wrong_reality_mismatch_uses_only_loopback_fallback("public-key")

    def _assert_wrong_reality_mismatch_uses_only_loopback_fallback(
        self, mismatch_kind: str
    ) -> None:
        if mismatch_kind == "short-id":
            mismatch_field, mismatch_label = "shortId", "short-ID"
        elif mismatch_kind == "public-key":
            mismatch_field, mismatch_label = "publicKey", "public-key"
        else:
            raise ValueError(f"unsupported REALITY mismatch kind: {mismatch_kind}")
        try:
            executable, metadata = xray.verify_binary()
        except RuntimeError as exc:
            self.skipTest(f"pinned Xray binary is unavailable: {exc}")

        body_secret = secrets.token_hex(24)
        body = ("transitvpn-reality-certification:" + body_secret).encode("ascii")
        keys = generate_keys()
        keys_to_scan = [
            keys.vless_uuid, keys.reality_private_key,
            keys.reality_public_key, keys.ss_password,
        ]
        server_short_id = generate_short_id()
        wrong_short_id = (
            "1" if server_short_id[0] == "0" else "0"
        ) + server_short_id[1:]
        self.assertNotEqual(server_short_id, wrong_short_id)
        server_name = "cover.example.test"

        responder: certification._Responder | None = None
        target: _RealityTarget | None = None
        responder_thread: threading.Thread | None = None
        target_thread: threading.Thread | None = None
        responder_started = False
        target_started = False
        server_process: object | None = None
        client_process: object | None = None
        cleanup_failed = False

        with tempfile.TemporaryDirectory(prefix="transitvpn-reality-local-") as directory:
            root = Path(directory)
            server_path = root / "server.json"
            matching_client_path = root / "client-matching.json"
            wrong_client_path = root / f"client-wrong-{mismatch_kind}.json"
            server_process = None
            client_process = None
            try:
                certificate_path, key_path = _write_local_target_certificate(
                    root, server_name
                )
                # Xray REALITY mirrors a TLS 1.3 target ServerHello; raw TCP
                # acceptance alone is not a valid local target.
                target_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                target_tls.minimum_version = ssl.TLSVersion.TLSv1_3
                target_tls.maximum_version = ssl.TLSVersion.TLSv1_3
                target_tls.load_cert_chain(str(certificate_path), str(key_path))

                responder = certification._Responder(body)
                target = _RealityTarget(target_tls)
                responder_thread = threading.Thread(
                    target=responder.serve_forever, daemon=True
                )
                target_thread = threading.Thread(
                    target=target.serve_forever, daemon=True
                )
                responder_thread.start()
                responder_started = True
                target_thread.start()
                target_started = True

                used_ports = {
                    int(responder.server_address[1]),
                    int(target.server_address[1]),
                }

                def unused_loopback_port() -> int:
                    while True:
                        port = certification._ephemeral_port()
                        if port not in used_ports:
                            used_ports.add(port)
                            return port

                server_port = unused_loopback_port()
                socks_port = unused_loopback_port()
                deployment = XrayDeployment(
                    keys=keys,
                    server=_LOOPBACK,
                    target=f"{_LOOPBACK}:{target.server_address[1]}",
                    server_name=server_name,
                    short_id=server_short_id,
                    target_verified=True,
                    port=server_port,
                    socks_port=socks_port,
                )
                server_config = build_server_config(deployment)
                server_config["inbounds"][0]["listen"] = _LOOPBACK
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
                if mismatch_kind == "short-id":
                    wrong_deployment = replace(deployment, short_id=wrong_short_id)
                else:
                    mismatched_keys = generate_keys()
                    self.assertNotEqual(
                        keys.reality_public_key, mismatched_keys.reality_public_key
                    )
                    keys_to_scan.extend((
                        mismatched_keys.vless_uuid, mismatched_keys.reality_private_key,
                        mismatched_keys.reality_public_key, mismatched_keys.ss_password,
                    ))
                    wrong_deployment = replace(
                        deployment,
                        keys=replace(
                            deployment.keys,
                            reality_public_key=mismatched_keys.reality_public_key,
                        ),
                    )
                    self.assertEqual(wrong_deployment.keys.vless_uuid, deployment.keys.vless_uuid)
                    self.assertEqual(
                        wrong_deployment.keys.reality_private_key,
                        deployment.keys.reality_private_key,
                    )
                    self.assertEqual(wrong_deployment.short_id, deployment.short_id)
                matching_client_config = build_client_config(deployment)
                wrong_client_config = build_client_config(wrong_deployment)

                validation = xray.validate_configs(
                    {
                        "server": server_config,
                        "client": matching_client_config,
                        "wrong-client": wrong_client_config,
                    },
                    binary=executable,
                )
                self.assertEqual(validation["version"], xray.XRAY_VERSION)
                self.assertEqual(validation["sha256"], metadata.executable_sha256)
                server_reality = server_config["inbounds"][0]["streamSettings"][
                    "realitySettings"
                ]
                matching_reality = matching_client_config["outbounds"][0][
                    "streamSettings"
                ]["realitySettings"]
                wrong_reality = wrong_client_config["outbounds"][0]["streamSettings"][
                    "realitySettings"
                ]
                self.assertEqual(server_reality["shortIds"], [server_short_id])
                self.assertEqual(matching_reality["shortId"], server_short_id)
                self.assertEqual(server_reality["serverNames"], [server_name])
                self.assertEqual(matching_reality["serverName"], server_name)
                if mismatch_kind == "short-id":
                    self.assertNotIn(wrong_short_id, server_reality["shortIds"])
                    self.assertEqual(wrong_reality["shortId"], wrong_short_id)
                else:
                    self.assertEqual(wrong_reality["shortId"], server_short_id)
                    self.assertEqual(matching_reality["publicKey"], keys.reality_public_key)
                    self.assertEqual(
                        wrong_reality["publicKey"], mismatched_keys.reality_public_key
                    )
                normalized_wrong_config = json.loads(json.dumps(wrong_client_config))
                normalized_reality = normalized_wrong_config["outbounds"][0][
                    "streamSettings"
                ]["realitySettings"]
                normalized_reality[mismatch_field] = matching_reality[mismatch_field]
                self.assertEqual(normalized_wrong_config, matching_client_config)

                certification._write_config(server_path, server_config)
                certification._write_config(matching_client_path, matching_client_config)
                certification._write_config(wrong_client_path, wrong_client_config)

                deadline = time.monotonic() + 10.0
                server_process = certification._start(executable, server_path, "server")
                certification._wait_ready(server_process, server_port, "server", deadline)
                client_process = certification._start(
                    executable, matching_client_path, "client"
                )
                certification._wait_ready(client_process, socks_port, "client", deadline)
                target_connections_before_positive = target.connection_count
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                response_bytes = certification._probe(
                    socks_port,
                    int(responder.server_address[1]),
                    body,
                    remaining,
                )
                self.assertEqual(response_bytes, len(body))
                self.assertEqual(responder.request_count, 1)
                self.assertGreater(
                    target.connection_count, target_connections_before_positive
                )
                self.assertIsNone(server_process.poll())
                self.assertTrue(certification._stop(client_process))
                client_process = None

                target_connections_before_mismatch = target.connection_count
                responder_requests_before_mismatch = responder.request_count
                client_process = certification._start(
                    executable, wrong_client_path, "client"
                )
                certification._wait_ready(
                    client_process, socks_port, "client", time.monotonic() + 10.0
                )
                with self.assertRaises(certification.XrayCertificationError) as raised:
                    certification._probe(
                        socks_port,
                        int(responder.server_address[1]),
                        body,
                        timeout=5.0,
                    )
                self.assertNotIn("timed out", str(raised.exception).lower())
                self.assertGreater(
                    target.connection_count, target_connections_before_mismatch
                )
                self.assertEqual(
                    responder.request_count, responder_requests_before_mismatch
                )
                self.assertIsNone(server_process.poll())
                self.assertIsNone(client_process.poll())
            finally:
                try:
                    certification._stop_all(client_process, server_process)
                except Exception:
                    cleanup_failed = True
                for server, thread, started in (
                    (target, target_thread, target_started),
                    (responder, responder_thread, responder_started),
                ):
                    if server is None:
                        continue
                    if thread is not None and started:
                        if not certification._stop_responder(server, thread):
                            cleanup_failed = True
                    else:
                        try:
                            server.server_close()
                        except Exception:
                            cleanup_failed = True
                if cleanup_failed:
                    raise certification.XrayCertificationError(
                        f"REALITY {mismatch_label} mismatch test cleanup could not be confirmed"
                    )

        _assert_absent_from_repository(
            self,
            (
                body_secret,
                *keys_to_scan,
                server_short_id,
                wrong_short_id,
            ),
        )

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
