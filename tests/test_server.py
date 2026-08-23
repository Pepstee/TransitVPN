"""Adversarial tests for transitvpn/server.py — independent check, no mocking of unit under test."""

from __future__ import annotations

import json
import uuid

import pytest

from transitvpn.keygen import Keys, generate_keys
from transitvpn.server import build_ss_config, build_xray_config


# ---------------------------------------------------------------------------
# Fixtures — real Keys, no mocking
# ---------------------------------------------------------------------------


@pytest.fixture()
def keys() -> Keys:
    return generate_keys()


@pytest.fixture()
def xray(keys: Keys) -> dict:
    return build_xray_config(keys)


@pytest.fixture()
def ss(keys: Keys) -> dict:
    return build_ss_config(keys)


def _inbound(cfg: dict) -> dict:
    return cfg["inbounds"][0]


def _settings(cfg: dict) -> dict:
    return _inbound(cfg)["settings"]


def _stream(cfg: dict) -> dict:
    return _inbound(cfg)["streamSettings"]


def _reality(cfg: dict) -> dict:
    return _stream(cfg)["realitySettings"]


# ---------------------------------------------------------------------------
# build_xray_config — top-level shape
# ---------------------------------------------------------------------------


class TestXrayTopLevelShape:
    def test_inbounds_key_present(self, xray):
        assert "inbounds" in xray

    def test_outbounds_key_present(self, xray):
        assert "outbounds" in xray

    def test_inbounds_is_list(self, xray):
        assert isinstance(xray["inbounds"], list)

    def test_outbounds_is_list(self, xray):
        assert isinstance(xray["outbounds"], list)

    def test_inbounds_has_one_entry(self, xray):
        assert len(xray["inbounds"]) == 1

    def test_outbounds_has_one_entry(self, xray):
        assert len(xray["outbounds"]) == 1

    def test_no_unexpected_top_level_keys(self, xray):
        assert set(xray.keys()) == {"inbounds", "outbounds"}


# ---------------------------------------------------------------------------
# build_xray_config — inbound / VLESS protocol
# ---------------------------------------------------------------------------


class TestXrayInbound:
    def test_protocol_is_vless(self, xray):
        assert _inbound(xray)["protocol"] == "vless"

    def test_protocol_value_is_lowercase(self, xray):
        assert _inbound(xray)["protocol"] == _inbound(xray)["protocol"].lower()

    def test_default_port_is_443(self, xray):
        assert _inbound(xray)["port"] == 443

    def test_port_is_int_not_string(self, xray):
        assert isinstance(_inbound(xray)["port"], int)

    def test_settings_key_present(self, xray):
        assert "settings" in _inbound(xray)

    def test_stream_settings_key_present(self, xray):
        assert "streamSettings" in _inbound(xray)

    def test_custom_port_is_applied(self, keys):
        cfg = build_xray_config(keys, port=8443)
        assert _inbound(cfg)["port"] == 8443

    def test_port_1_is_accepted(self, keys):
        cfg = build_xray_config(keys, port=1)
        assert _inbound(cfg)["port"] == 1

    def test_port_65535_is_accepted(self, keys):
        cfg = build_xray_config(keys, port=65535)
        assert _inbound(cfg)["port"] == 65535


# ---------------------------------------------------------------------------
# build_xray_config — VLESS client settings
# ---------------------------------------------------------------------------


class TestXrayVlessClientSettings:
    def test_clients_present(self, xray):
        assert "clients" in _settings(xray)

    def test_clients_is_list(self, xray):
        assert isinstance(_settings(xray)["clients"], list)

    def test_clients_has_exactly_one_entry(self, xray):
        assert len(_settings(xray)["clients"]) == 1

    def test_client_id_matches_keys_vless_uuid(self, keys):
        cfg = build_xray_config(keys)
        assert _settings(cfg)["clients"][0]["id"] == keys.vless_uuid

    def test_client_id_is_not_hardcoded(self):
        # Two different Keys objects must produce different client ids.
        k1, k2 = generate_keys(), generate_keys()
        id1 = _settings(build_xray_config(k1))["clients"][0]["id"]
        id2 = _settings(build_xray_config(k2))["clients"][0]["id"]
        assert id1 != id2

    def test_client_id_is_valid_uuid(self, keys):
        cfg = build_xray_config(keys)
        client_id = _settings(cfg)["clients"][0]["id"]
        parsed = uuid.UUID(client_id)
        assert str(parsed) == client_id

    def test_client_flow_is_xtls_rprx_vision(self, xray):
        assert _settings(xray)["clients"][0]["flow"] == "xtls-rprx-vision"

    def test_decryption_is_string_none(self, xray):
        # "none" as a string, NOT Python None
        decryption = _settings(xray)["decryption"]
        assert decryption == "none"
        assert isinstance(decryption, str)

    def test_decryption_is_not_python_none(self, xray):
        assert _settings(xray)["decryption"] is not None


# ---------------------------------------------------------------------------
# build_xray_config — stream / REALITY security
# ---------------------------------------------------------------------------


class TestXrayStreamSettings:
    def test_network_is_tcp(self, xray):
        assert _stream(xray)["network"] == "tcp"

    def test_security_is_reality(self, xray):
        assert _stream(xray)["security"] == "reality"

    def test_security_is_not_tls(self, xray):
        assert _stream(xray)["security"] != "tls"

    def test_reality_settings_present(self, xray):
        assert "realitySettings" in _stream(xray)


class TestXrayRealitySettings:
    def test_show_is_bool_false(self, xray):
        # Must be Python False (bool), not any other falsy value.
        show = _reality(xray)["show"]
        assert show is False
        assert isinstance(show, bool)

    def test_default_dest_is_microsoft(self, xray):
        assert _reality(xray)["dest"] == "www.microsoft.com:443"

    def test_custom_dest_applied(self, keys):
        cfg = build_xray_config(keys, dest="www.google.com:443")
        assert _reality(cfg)["dest"] == "www.google.com:443"

    def test_xver_is_int_zero(self, xray):
        xver = _reality(xray)["xver"]
        assert xver == 0
        assert isinstance(xver, int)

    def test_server_names_is_list(self, xray):
        assert isinstance(_reality(xray)["serverNames"], list)

    def test_default_server_names_contains_microsoft(self, xray):
        assert "www.microsoft.com" in _reality(xray)["serverNames"]

    def test_default_server_names_has_one_entry(self, xray):
        assert len(_reality(xray)["serverNames"]) == 1

    def test_custom_server_names_applied(self, keys):
        names = ["vpn.example.com", "backup.example.com"]
        cfg = build_xray_config(keys, server_names=names)
        assert _reality(cfg)["serverNames"] == names

    def test_server_names_none_gives_default(self, keys):
        cfg = build_xray_config(keys, server_names=None)
        assert _reality(cfg)["serverNames"] == ["www.microsoft.com"]

    def test_private_key_matches_keys_field(self, keys):
        cfg = build_xray_config(keys)
        assert _reality(cfg)["privateKey"] == keys.reality_private_key

    def test_private_key_is_string(self, keys):
        cfg = build_xray_config(keys)
        assert isinstance(_reality(cfg)["privateKey"], str)

    def test_private_key_is_not_public_key(self, keys):
        cfg = build_xray_config(keys)
        assert _reality(cfg)["privateKey"] != keys.reality_public_key

    def test_private_key_differs_between_different_keys(self):
        k1, k2 = generate_keys(), generate_keys()
        pk1 = _reality(build_xray_config(k1))["privateKey"]
        pk2 = _reality(build_xray_config(k2))["privateKey"]
        assert pk1 != pk2

    def test_short_ids_is_list(self, xray):
        assert isinstance(_reality(xray)["shortIds"], list)

    def test_default_short_ids_is_list_with_empty_string(self, xray):
        assert _reality(xray)["shortIds"] == [""]

    def test_custom_short_ids_applied(self, keys):
        ids = ["a1b2c3d4", "e5f6a7b8"]
        cfg = build_xray_config(keys, short_ids=ids)
        assert _reality(cfg)["shortIds"] == ids

    def test_short_ids_none_gives_default(self, keys):
        cfg = build_xray_config(keys, short_ids=None)
        assert _reality(cfg)["shortIds"] == [""]

    def test_all_required_reality_fields_present(self, xray):
        required = {"show", "dest", "xver", "serverNames", "privateKey", "shortIds"}
        assert required.issubset(_reality(xray).keys())


# ---------------------------------------------------------------------------
# build_xray_config — outbound
# ---------------------------------------------------------------------------


class TestXrayOutbound:
    def test_outbound_protocol_is_freedom(self, xray):
        assert xray["outbounds"][0]["protocol"] == "freedom"

    def test_outbound_tag_is_direct(self, xray):
        assert xray["outbounds"][0]["tag"] == "direct"


# ---------------------------------------------------------------------------
# build_xray_config — mutable-default isolation
# ---------------------------------------------------------------------------


class TestXrayMutableDefaultIsolation:
    """Mutations to one call's output must never bleed into the next call's defaults."""

    def test_mutating_returned_server_names_does_not_affect_next_default(self, keys):
        cfg1 = build_xray_config(keys)
        _reality(cfg1)["serverNames"].append("attacker.com")

        cfg2 = build_xray_config(keys)
        assert "attacker.com" not in _reality(cfg2)["serverNames"]

    def test_mutating_returned_short_ids_does_not_affect_next_default(self, keys):
        cfg1 = build_xray_config(keys)
        _reality(cfg1)["shortIds"].append("leaked_id")

        cfg2 = build_xray_config(keys)
        assert "leaked_id" not in _reality(cfg2)["shortIds"]

    def test_mutating_clients_does_not_change_keys_uuid(self, keys):
        original_uuid = keys.vless_uuid
        cfg = build_xray_config(keys)
        _settings(cfg)["clients"][0]["id"] = "overwritten"
        assert keys.vless_uuid == original_uuid


# ---------------------------------------------------------------------------
# build_xray_config — JSON round-trip
# ---------------------------------------------------------------------------


class TestXrayJsonRoundtrip:
    def test_config_is_json_serializable(self, xray):
        dumped = json.dumps(xray)
        assert isinstance(dumped, str)

    def test_json_roundtrip_preserves_identity(self, xray):
        assert json.loads(json.dumps(xray)) == xray

    def test_json_contains_vless_literal(self, xray):
        assert '"vless"' in json.dumps(xray)

    def test_json_contains_reality_literal(self, xray):
        assert '"reality"' in json.dumps(xray)

    def test_json_show_is_false_not_null(self, xray):
        raw = json.dumps(xray)
        parsed = json.loads(raw)
        assert parsed["inbounds"][0]["streamSettings"]["realitySettings"]["show"] is False

    def test_json_server_names_survive_roundtrip(self, keys):
        names = ["vpn.example.com", "alt.example.com"]
        cfg = build_xray_config(keys, server_names=names)
        restored = json.loads(json.dumps(cfg))
        assert restored["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"] == names

    def test_json_port_is_number_not_string(self, xray):
        parsed = json.loads(json.dumps(xray))
        assert isinstance(parsed["inbounds"][0]["port"], int)


# ---------------------------------------------------------------------------
# build_ss_config — structure
# ---------------------------------------------------------------------------


class TestSsConfigStructure:
    def test_server_key_present(self, ss):
        assert "server" in ss

    def test_server_port_key_present(self, ss):
        assert "server_port" in ss

    def test_password_key_present(self, ss):
        assert "password" in ss

    def test_method_key_present(self, ss):
        assert "method" in ss

    def test_mode_key_present(self, ss):
        assert "mode" in ss

    def test_all_required_fields_present(self, ss):
        assert {"server", "server_port", "password", "method", "mode"}.issubset(ss.keys())


# ---------------------------------------------------------------------------
# build_ss_config — default values
# ---------------------------------------------------------------------------


class TestSsConfigDefaults:
    def test_default_server_is_all_interfaces(self, ss):
        assert ss["server"] == "0.0.0.0"

    def test_default_server_port_is_8388(self, ss):
        assert ss["server_port"] == 8388

    def test_default_method_is_ss2022_aes256gcm(self, ss):
        assert ss["method"] == "2022-blake3-aes-256-gcm"

    def test_default_method_starts_with_2022(self, ss):
        # The method must be a Shadowsocks-2022 cipher.
        assert ss["method"].startswith("2022-")

    def test_mode_is_tcp_and_udp(self, ss):
        assert ss["mode"] == "tcp_and_udp"

    def test_server_port_is_int(self, ss):
        assert isinstance(ss["server_port"], int)


# ---------------------------------------------------------------------------
# build_ss_config — keys wired correctly
# ---------------------------------------------------------------------------


class TestSsConfigKeys:
    def test_password_matches_keys_ss_password(self, keys):
        cfg = build_ss_config(keys)
        assert cfg["password"] == keys.ss_password

    def test_password_is_string(self, ss):
        assert isinstance(ss["password"], str)

    def test_password_is_not_empty(self, ss):
        assert ss["password"] != ""

    def test_password_differs_between_different_keys(self):
        k1, k2 = generate_keys(), generate_keys()
        assert build_ss_config(k1)["password"] != build_ss_config(k2)["password"]

    def test_password_is_not_uuid_field(self, keys):
        cfg = build_ss_config(keys)
        assert cfg["password"] != keys.vless_uuid

    def test_password_is_not_private_key_field(self, keys):
        cfg = build_ss_config(keys)
        assert cfg["password"] != keys.reality_private_key


# ---------------------------------------------------------------------------
# build_ss_config — custom arguments
# ---------------------------------------------------------------------------


class TestSsConfigCustomArgs:
    def test_custom_server_address(self, keys):
        cfg = build_ss_config(keys, server="192.168.1.10")
        assert cfg["server"] == "192.168.1.10"

    def test_custom_port(self, keys):
        cfg = build_ss_config(keys, port=9999)
        assert cfg["server_port"] == 9999

    def test_custom_method_is_stored(self, keys):
        cfg = build_ss_config(keys, method="2022-blake3-chacha20-poly1305")
        assert cfg["method"] == "2022-blake3-chacha20-poly1305"

    def test_custom_method_does_not_alter_password(self, keys):
        cfg = build_ss_config(keys, method="2022-blake3-chacha20-poly1305")
        assert cfg["password"] == keys.ss_password

    def test_custom_server_does_not_alter_password(self, keys):
        cfg = build_ss_config(keys, server="10.0.0.1")
        assert cfg["password"] == keys.ss_password


# ---------------------------------------------------------------------------
# build_ss_config — JSON round-trip
# ---------------------------------------------------------------------------


class TestSsConfigJsonRoundtrip:
    def test_config_is_json_serializable(self, ss):
        assert isinstance(json.dumps(ss), str)

    def test_json_roundtrip_preserves_identity(self, ss):
        assert json.loads(json.dumps(ss)) == ss

    def test_json_server_port_is_number_not_string(self, ss):
        parsed = json.loads(json.dumps(ss))
        assert isinstance(parsed["server_port"], int)

    def test_json_contains_ss2022_method(self, ss):
        assert "2022-blake3-aes-256-gcm" in json.dumps(ss)

    def test_json_password_survives_roundtrip(self, keys):
        cfg = build_ss_config(keys)
        restored = json.loads(json.dumps(cfg))
        assert restored["password"] == keys.ss_password


# ---------------------------------------------------------------------------
# Cross-function independence
# ---------------------------------------------------------------------------


class TestCrossFunctionIndependence:
    def test_xray_and_ss_configs_from_same_keys_have_independent_passwords(self, keys):
        xray_cfg = build_xray_config(keys)
        ss_cfg = build_ss_config(keys)
        # The ss password must not appear as the VLESS client id or private key.
        vless_id = _settings(xray_cfg)["clients"][0]["id"]
        private_key = _reality(xray_cfg)["privateKey"]
        assert ss_cfg["password"] != vless_id
        assert ss_cfg["password"] != private_key

    def test_repeated_xray_calls_return_equal_configs_for_same_keys(self, keys):
        cfg1 = build_xray_config(keys)
        cfg2 = build_xray_config(keys)
        assert cfg1 == cfg2

    def test_repeated_ss_calls_return_equal_configs_for_same_keys(self, keys):
        cfg1 = build_ss_config(keys)
        cfg2 = build_ss_config(keys)
        assert cfg1 == cfg2
