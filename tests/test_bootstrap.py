"""Hermetic bootstrap contract tests with a controlled binary-validation boundary.

Real pinned-binary validation and tunnel operation have separate integration tests.
These exercise the actual CLI, generation and permission-restricted persistence.
"""
from __future__ import annotations

import json
import stat
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from transitvpn.cli import main
from transitvpn.xray import XRAY_VERSION


_ARGUMENTS = [
    "--host", "vpn.example", "--target", "verified-target.example:443",
    "--server-name", "verified-target.example", "--target-verified",
    "--xray-binary", "synthetic-test-xray",
]
_IDENTITY = {"version": XRAY_VERSION, "sha256": "0" * 64,
             "checksum_source": "https://example.invalid/synthetic-test.dgst"}
_FILES = ("xray-server.json", "xray-client.json", "xray-identity.json")


@pytest.fixture()
def run_in_tmp(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    def run(argv=None, *, failure=None):
        arguments = list(argv if argv is not None else ["bootstrap"])
        with patch("transitvpn.xray.validate_configs", return_value=dict(_IDENTITY),
                   side_effect=failure) as validation:
            code = main(arguments + _ARGUMENTS)
        captured = capsys.readouterr()
        run.observed = SimpleNamespace(validation=validation, stdout=captured.out,
                                       stderr=captured.err)
        return code, captured.out

    return run


def read_state(tmp_path, name):
    return json.loads((tmp_path / "state" / name).read_text())


class TestBootstrapRequiredArguments:
    @pytest.mark.parametrize("option", ["--host", "--target", "--server-name",
                                        "--target-verified"])
    def test_missing_required_argument_is_rejected(self, tmp_path, monkeypatch, option):
        monkeypatch.chdir(tmp_path)
        arguments = list(_ARGUMENTS)
        index = arguments.index(option)
        del arguments[index:index + (1 if option == "--target-verified" else 2)]
        with pytest.raises(SystemExit) as raised:
            main(["bootstrap", *arguments])
        assert raised.value.code == 2
        assert not (tmp_path / "state").exists()

    def test_no_implicit_host_or_target(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with pytest.raises(SystemExit) as raised:
            main(["bootstrap"])
        assert raised.value.code == 2
        assert not (tmp_path / "state").exists()


class TestBootstrapEndpointOptions:
    ENDPOINT = ["--listen", "127.0.0.1", "--port", "18443",
                "--socks-port", "18080"]

    def test_selected_endpoints_are_written_to_matching_configs(
        self, run_in_tmp, tmp_path
    ):
        code, _ = run_in_tmp(["bootstrap", *self.ENDPOINT])
        assert code == 0
        server = read_state(tmp_path, "xray-server.json")
        client = read_state(tmp_path, "xray-client.json")
        inbound = server["inbounds"][0]
        peer = client["outbounds"][0]["settings"]["vnext"][0]
        socks = client["inbounds"][0]
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["port"] == 18443
        assert peer["address"] == "vpn.example"
        assert peer["port"] == inbound["port"]
        assert socks["listen"] == "127.0.0.1"
        assert socks["port"] == 18080

    def test_omitted_options_preserve_existing_defaults(self, run_in_tmp, tmp_path):
        run_in_tmp()
        server = read_state(tmp_path, "xray-server.json")
        client = read_state(tmp_path, "xray-client.json")
        assert "listen" not in server["inbounds"][0]
        assert server["inbounds"][0]["port"] == 443
        assert client["inbounds"][0]["listen"] == "127.0.0.1"
        assert client["inbounds"][0]["port"] == 10808

    @pytest.mark.parametrize("listen", ["vpn.example", "127.0.0.1:443",
                                        "256.0.0.1", ""])
    def test_non_ip_listener_is_rejected_before_key_generation(
        self, tmp_path, monkeypatch, listen
    ):
        monkeypatch.chdir(tmp_path)
        with patch("transitvpn.keygen.generate_keys") as keygen:
            with patch("transitvpn.keygen.generate_short_id") as short_id:
                with pytest.raises(SystemExit) as raised:
                    main(["bootstrap", "--listen", listen, *_ARGUMENTS])
        assert raised.value.code == 2
        keygen.assert_not_called()
        short_id.assert_not_called()
        assert not (tmp_path / "state").exists()

    @pytest.mark.parametrize("option,value", [
        ("--port", "0"), ("--port", "65536"), ("--port", "-1"),
        ("--port", "bad"), ("--socks-port", "0"),
        ("--socks-port", "65536"), ("--socks-port", "bad"),
    ])
    def test_invalid_port_is_rejected_before_key_generation(
        self, tmp_path, monkeypatch, option, value
    ):
        monkeypatch.chdir(tmp_path)
        with patch("transitvpn.keygen.generate_keys") as keygen:
            with patch("transitvpn.keygen.generate_short_id") as short_id:
                with pytest.raises(SystemExit) as raised:
                    main(["bootstrap", option, value, *_ARGUMENTS])
        assert raised.value.code == 2
        keygen.assert_not_called()
        short_id.assert_not_called()
        assert not (tmp_path / "state").exists()

class TestBootstrapReturnCode:
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_validated_run_returns_zero(self, run_in_tmp, dry_run):
        code, _ = run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []))
        assert code == 0

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_validation_failure_is_closed(self, run_in_tmp, tmp_path, dry_run):
        code, out = run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []),
                               failure=RuntimeError("pinned binary unavailable"))
        assert code == 1
        assert "pinned binary unavailable" in run_in_tmp.observed.stderr
        assert "validated" not in out and "wrote" not in out
        assert not (tmp_path / "state").exists()


class TestBootstrapFileCreation:
    @pytest.mark.parametrize("name", _FILES)
    def test_generated_file_is_valid_json(self, run_in_tmp, tmp_path, name):
        run_in_tmp()
        assert isinstance(read_state(tmp_path, name), dict)

    @pytest.mark.parametrize("name", _FILES)
    def test_dry_run_does_not_write_files(self, run_in_tmp, tmp_path, name):
        run_in_tmp(["bootstrap", "--dry-run"])
        assert not (tmp_path / "state" / name).exists()

    def test_exact_generated_files(self, run_in_tmp, tmp_path):
        run_in_tmp()
        assert {p.name for p in (tmp_path / "state").iterdir()} == set(_FILES)

    def test_dry_run_does_not_create_state(self, run_in_tmp, tmp_path):
        run_in_tmp(["bootstrap", "--dry-run"])
        assert not (tmp_path / "state").exists()

    @pytest.mark.parametrize("name", _FILES)
    def test_files_are_owner_only(self, run_in_tmp, tmp_path, name):
        run_in_tmp()
        assert stat.S_IMODE((tmp_path / "state" / name).stat().st_mode) == 0o600

    def test_state_directory_is_owner_only(self, run_in_tmp, tmp_path):
        run_in_tmp()
        assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700

    def test_existing_state_permissions_are_restricted(self, run_in_tmp, tmp_path):
        state = tmp_path / "state"
        state.mkdir(mode=0o755)
        state.chmod(0o755)
        run_in_tmp()
        assert stat.S_IMODE(state.stat().st_mode) == 0o700


class TestXrayJsonStructure:
    @pytest.fixture()
    def xray(self, run_in_tmp, tmp_path) -> dict:
        run_in_tmp(["bootstrap"])
        return json.loads((tmp_path / "state" / "xray-server.json").read_text())

    def test_inbounds_key_present(self, xray) -> None:
        assert "inbounds" in xray

    def test_outbounds_key_present(self, xray) -> None:
        assert "outbounds" in xray

    def test_inbounds_is_list(self, xray) -> None:
        assert isinstance(xray["inbounds"], list)

    def test_inbounds_is_not_empty(self, xray) -> None:
        assert len(xray["inbounds"]) >= 1

    def test_outbounds_is_not_empty(self, xray) -> None:
        assert len(xray["outbounds"]) >= 1

    def test_inbound_protocol_is_vless(self, xray) -> None:
        assert xray["inbounds"][0]["protocol"] == "vless"

    def test_inbound_stream_has_reality(self, xray) -> None:
        stream = xray["inbounds"][0]["streamSettings"]
        assert stream["security"] == "reality"

    def test_inbound_has_port_443(self, xray) -> None:
        assert xray["inbounds"][0]["port"] == 443

    def test_reality_private_key_present(self, xray) -> None:
        reality = xray["inbounds"][0]["streamSettings"]["realitySettings"]
        assert "privateKey" in reality
        assert isinstance(reality["privateKey"], str)
        assert reality["privateKey"] != ""

    def test_vless_client_id_is_present(self, xray) -> None:
        clients = xray["inbounds"][0]["settings"]["clients"]
        assert len(clients) >= 1
        assert "id" in clients[0]

    def test_outbound_protocol_is_freedom(self, xray) -> None:
        assert xray["outbounds"][0]["protocol"] == "freedom"

    def test_json_roundtrip_preserves_identity(self, xray) -> None:
        re_parsed = json.loads(json.dumps(xray))
        assert re_parsed == xray


class TestMatchedClientAndServer:
    @pytest.fixture()
    def peers(self, run_in_tmp, tmp_path):
        run_in_tmp()
        return (read_state(tmp_path, "xray-server.json"),
                read_state(tmp_path, "xray-client.json"))

    def test_client_uses_explicit_host_and_server_port(self, peers):
        server, client = peers
        endpoint = client["outbounds"][0]["settings"]["vnext"][0]
        assert endpoint["address"] == "vpn.example"
        assert endpoint["port"] == server["inbounds"][0]["port"] == 443

    def test_uuid_and_flow_match(self, peers):
        server, client = peers
        account = server["inbounds"][0]["settings"]["clients"][0]
        user = client["outbounds"][0]["settings"]["vnext"][0]["users"][0]
        assert user["id"] == account["id"]
        assert user["flow"] == account["flow"] == "xtls-rprx-vision"

    def test_sni_and_short_id_match(self, peers):
        server, client = peers
        reality = server["inbounds"][0]["streamSettings"]["realitySettings"]
        remote = client["outbounds"][0]["streamSettings"]["realitySettings"]
        assert reality["target"] == "verified-target.example:443"
        assert reality["serverNames"] == [remote["serverName"]] == ["verified-target.example"]
        assert reality["shortIds"] == [remote["shortId"]]
        assert len(remote["shortId"]) == 16
        assert int(remote["shortId"], 16) >= 0

    def test_public_key_cryptographically_matches_private_key(self, peers):
        import base64
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        server, client = peers
        reality = server["inbounds"][0]["streamSettings"]["realitySettings"]
        remote = client["outbounds"][0]["streamSettings"]["realitySettings"]
        raw = base64.urlsafe_b64decode(reality["privateKey"] + "=")
        public = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        assert base64.urlsafe_b64encode(public).decode().rstrip("=") == remote["publicKey"]

    def test_client_has_loopback_socks_only(self, peers):
        _, client = peers
        assert len(client["inbounds"]) == 1
        inbound = client["inbounds"][0]
        assert inbound["protocol"] == "socks"
        assert inbound["listen"] == "127.0.0.1"
        assert inbound["port"] == 10808

    def test_client_has_no_direct_fallback(self, peers):
        _, client = peers
        assert len(client["outbounds"]) == 1
        assert client["outbounds"][0]["protocol"] == "vless"

    @pytest.mark.parametrize("role", [0, 1])
    def test_both_peers_use_reality_raw(self, peers, role):
        section = "inbounds" if role == 0 else "outbounds"
        stream = peers[role][section][0]["streamSettings"]
        assert stream["network"] == "raw"
        assert stream["security"] == "reality"


class TestBootstrapValidationAndIdentity:
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_both_configs_validated_with_explicit_binary(self, run_in_tmp, tmp_path, dry_run):
        run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []))
        validation = run_in_tmp.observed.validation
        validation.assert_called_once()
        configs, binary = validation.call_args.args
        assert set(configs) == {"server", "client"}
        assert binary == "synthetic-test-xray"
        if not dry_run:
            for role in configs:
                assert read_state(tmp_path, f"xray-{role}.json") == configs[role]

    def test_identity_records_only_observed_scope(self, run_in_tmp, tmp_path):
        run_in_tmp()
        identity = read_state(tmp_path, "xray-identity.json")
        assert {key: identity[key] for key in _IDENTITY} == _IDENTITY
        assert identity["local_evidence"] == {
            "scope": "configuration-validation", "xray_configuration": "observed"}
        assert identity["external_recovery"] == {"status": "unprovisioned", "observed": False}

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_no_network_discovery(self, run_in_tmp, dry_run):
        with patch("transitvpn.cgnat.detect_cgnat") as discovery:
            run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []))
        discovery.assert_not_called()


class TestBootstrapOutputAndRotation:
    @pytest.mark.parametrize("dry_run", [False, True])
    def test_stdout_contains_only_nonsecret_validation_evidence(self, run_in_tmp, dry_run):
        _, out = run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []))
        assert f"Xray {XRAY_VERSION}" in out
        assert _IDENTITY["sha256"] in out
        configs = run_in_tmp.observed.validation.call_args.args[0]
        server = configs["server"]["inbounds"][0]
        reality = server["streamSettings"]["realitySettings"]
        for value in [server["settings"]["clients"][0]["id"], reality["privateKey"],
                      reality["shortIds"][0]]:
            assert value not in out + run_in_tmp.observed.stderr
        assert "vless://" not in out and "ss://" not in out
        assert ("wrote" in out) is not dry_run

    def test_rotation_generates_new_credentials(self, run_in_tmp, tmp_path):
        run_in_tmp()
        first = read_state(tmp_path, "xray-server.json")["inbounds"][0]
        code, _ = run_in_tmp()
        second = read_state(tmp_path, "xray-server.json")["inbounds"][0]
        assert code == 0
        assert first["settings"]["clients"][0]["id"] != second["settings"]["clients"][0]["id"]
        for key in ("privateKey", "shortIds"):
            assert first["streamSettings"]["realitySettings"][key] != second["streamSettings"]["realitySettings"][key]

    @pytest.mark.parametrize("dry_run", [False, True])
    def test_nonwriting_attempt_preserves_previous_state(self, run_in_tmp, tmp_path, dry_run):
        run_in_tmp()
        before = {name: (tmp_path / "state" / name).read_bytes() for name in _FILES}
        run_in_tmp(["bootstrap"] + (["--dry-run"] if dry_run else []),
                   failure=None if dry_run else RuntimeError("validation rejected"))
        after = {name: (tmp_path / "state" / name).read_bytes() for name in _FILES}
        assert after == before
