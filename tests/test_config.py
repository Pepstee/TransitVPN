"""Tests for transitvpn.config — dataclass validation and serialisation roundtrip."""

from __future__ import annotations

import dataclasses

import pytest

from transitvpn.config import RelayConfig, ShadowsocksConfig, VlessConfig


class TestVlessConfigValidation:
    def test_minimal_valid_config(self):
        cfg = VlessConfig(uuid="test-uuid", server="vpn.example.com")
        assert cfg.uuid == "test-uuid"
        assert cfg.server == "vpn.example.com"

    def test_empty_uuid_raises(self):
        with pytest.raises(ValueError, match="uuid"):
            VlessConfig(uuid="", server="vpn.example.com")

    def test_empty_server_raises(self):
        with pytest.raises(ValueError, match="server"):
            VlessConfig(uuid="test-uuid", server="")

    def test_port_zero_raises(self):
        with pytest.raises(ValueError, match="port"):
            VlessConfig(uuid="u", server="s", port=0)

    def test_port_65536_raises(self):
        with pytest.raises(ValueError, match="port"):
            VlessConfig(uuid="u", server="s", port=65536)

    def test_port_negative_raises(self):
        with pytest.raises(ValueError, match="port"):
            VlessConfig(uuid="u", server="s", port=-1)

    def test_port_boundary_low_valid(self):
        cfg = VlessConfig(uuid="u", server="s", port=1)
        assert cfg.port == 1

    def test_port_boundary_high_valid(self):
        cfg = VlessConfig(uuid="u", server="s", port=65535)
        assert cfg.port == 65535


class TestVlessConfigDefaults:
    def test_default_port(self):
        cfg = VlessConfig(uuid="u", server="s")
        assert cfg.port == 443

    def test_default_flow_empty(self):
        assert VlessConfig(uuid="u", server="s").flow == ""

    def test_default_network_tcp(self):
        assert VlessConfig(uuid="u", server="s").network == "tcp"

    def test_default_tls_true(self):
        assert VlessConfig(uuid="u", server="s").tls is True

    def test_default_sni_empty(self):
        assert VlessConfig(uuid="u", server="s").sni == ""

    def test_default_fingerprint_chrome(self):
        assert VlessConfig(uuid="u", server="s").fingerprint == "chrome"

    def test_default_public_key_empty(self):
        assert VlessConfig(uuid="u", server="s").public_key == ""

    def test_default_short_id_empty(self):
        assert VlessConfig(uuid="u", server="s").short_id == ""

    def test_default_path_empty(self):
        assert VlessConfig(uuid="u", server="s").path == ""

    def test_default_headers_empty_dict(self):
        assert VlessConfig(uuid="u", server="s").headers == {}

    def test_headers_are_independent_per_instance(self):
        c1 = VlessConfig(uuid="u", server="s")
        c2 = VlessConfig(uuid="u", server="s")
        c1.headers["k"] = "v"
        assert c2.headers == {}


class TestVlessConfigSerialisation:
    def test_asdict_roundtrip(self):
        original = VlessConfig(
            uuid="abc-123",
            server="vpn.example.com",
            port=8443,
            flow="xtls-rprx-vision",
            network="ws",
            tls=True,
            sni="vpn.example.com",
            fingerprint="firefox",
            public_key="pubkey",
            short_id="a1b2",
            path="/ws",
            headers={"Host": "example.com"},
        )
        d = dataclasses.asdict(original)
        restored = VlessConfig(**d)
        assert restored == original

    def test_asdict_has_all_fields(self):
        cfg = VlessConfig(uuid="u", server="s")
        d = dataclasses.asdict(cfg)
        expected = {f.name for f in dataclasses.fields(VlessConfig)}
        assert set(d.keys()) == expected

    def test_asdict_deep_copies_headers(self):
        cfg = VlessConfig(uuid="u", server="s", headers={"k": "v"})
        d = dataclasses.asdict(cfg)
        d["headers"]["k"] = "changed"
        assert cfg.headers["k"] == "v"

    def test_minimal_roundtrip_defaults_preserved(self):
        original = VlessConfig(uuid="u", server="s")
        restored = VlessConfig(**dataclasses.asdict(original))
        assert restored.port == 443
        assert restored.tls is True
        assert restored.fingerprint == "chrome"


class TestShadowsocksConfigValidation:
    def test_minimal_valid_config(self):
        cfg = ShadowsocksConfig(server="ss.example.com", port=8388, password="s3cr3t")
        assert cfg.server == "ss.example.com"

    def test_empty_server_raises(self):
        with pytest.raises(ValueError, match="server"):
            ShadowsocksConfig(server="", port=8388, password="p")

    def test_empty_password_raises(self):
        with pytest.raises(ValueError, match="password"):
            ShadowsocksConfig(server="s", port=8388, password="")

    def test_port_zero_raises(self):
        with pytest.raises(ValueError, match="port"):
            ShadowsocksConfig(server="s", port=0, password="p")

    def test_port_65536_raises(self):
        with pytest.raises(ValueError, match="port"):
            ShadowsocksConfig(server="s", port=65536, password="p")

    def test_port_negative_raises(self):
        with pytest.raises(ValueError, match="port"):
            ShadowsocksConfig(server="s", port=-1, password="p")

    def test_port_boundary_low_valid(self):
        cfg = ShadowsocksConfig(server="s", port=1, password="p")
        assert cfg.port == 1

    def test_port_boundary_high_valid(self):
        cfg = ShadowsocksConfig(server="s", port=65535, password="p")
        assert cfg.port == 65535


class TestShadowsocksConfigDefaults:
    def test_default_method_is_aes256gcm(self):
        cfg = ShadowsocksConfig(server="s", port=80, password="p")
        assert cfg.method == "aes-256-gcm"

    def test_default_plugin_empty(self):
        assert ShadowsocksConfig(server="s", port=80, password="p").plugin == ""

    def test_default_plugin_opts_empty(self):
        assert ShadowsocksConfig(server="s", port=80, password="p").plugin_opts == ""

    def test_custom_method_accepted(self):
        cfg = ShadowsocksConfig(server="s", port=80, password="p", method="chacha20-ietf-poly1305")
        assert cfg.method == "chacha20-ietf-poly1305"

    def test_supported_methods_frozenset_exists(self):
        methods = ShadowsocksConfig._SUPPORTED_METHODS
        assert isinstance(methods, frozenset)
        assert "aes-256-gcm" in methods
        assert "chacha20-ietf-poly1305" in methods
        assert "2022-blake3-aes-256-gcm" in methods

    def test_unsupported_method_rejected(self):
        with pytest.raises(ValueError, match="unsupported method"):
            ShadowsocksConfig(server="s", port=80, password="p", method="rot13")

    def test_every_supported_method_accepted(self):
        for method in ShadowsocksConfig._SUPPORTED_METHODS:
            cfg = ShadowsocksConfig(server="s", port=80, password="p", method=method)
            assert cfg.method == method


class TestShadowsocksConfigSerialisation:
    def test_asdict_roundtrip(self):
        original = ShadowsocksConfig(
            server="ss.example.com",
            port=8388,
            password="s3cr3t",
            method="chacha20-ietf-poly1305",
            plugin="obfs-local",
            plugin_opts="obfs=http;obfs-host=www.google.com",
        )
        restored = ShadowsocksConfig(**dataclasses.asdict(original))
        assert restored == original

    def test_asdict_has_all_fields(self):
        cfg = ShadowsocksConfig(server="s", port=80, password="p")
        d = dataclasses.asdict(cfg)
        expected = {f.name for f in dataclasses.fields(ShadowsocksConfig)}
        assert set(d.keys()) == expected

    def test_minimal_roundtrip_defaults_preserved(self):
        original = ShadowsocksConfig(server="s", port=80, password="p")
        restored = ShadowsocksConfig(**dataclasses.asdict(original))
        assert restored.method == "aes-256-gcm"
        assert restored.plugin == ""


class TestRelayConfigValidation:
    def test_minimal_valid_config(self):
        cfg = RelayConfig(name="relay1")
        assert cfg.name == "relay1"

    def test_empty_name_raises(self):
        with pytest.raises(ValueError, match="name"):
            RelayConfig(name="")

    def test_listen_port_zero_raises(self):
        with pytest.raises(ValueError, match="listen_port"):
            RelayConfig(name="r", listen_port=0)

    def test_listen_port_65536_raises(self):
        with pytest.raises(ValueError, match="listen_port"):
            RelayConfig(name="r", listen_port=65536)

    def test_listen_port_negative_raises(self):
        with pytest.raises(ValueError, match="listen_port"):
            RelayConfig(name="r", listen_port=-1)

    def test_listen_port_boundary_low_valid(self):
        cfg = RelayConfig(name="r", listen_port=1)
        assert cfg.listen_port == 1

    def test_listen_port_boundary_high_valid(self):
        cfg = RelayConfig(name="r", listen_port=65535)
        assert cfg.listen_port == 65535


class TestRelayConfigDefaults:
    def test_default_listen_address(self):
        assert RelayConfig(name="r").listen_address == "127.0.0.1"

    def test_default_listen_port(self):
        assert RelayConfig(name="r").listen_port == 10808

    def test_default_upstream_none(self):
        assert RelayConfig(name="r").upstream is None

    def test_default_tags_empty(self):
        assert RelayConfig(name="r").tags == []

    def test_tags_are_independent_per_instance(self):
        r1 = RelayConfig(name="r")
        r2 = RelayConfig(name="r")
        r1.tags.append("fast")
        assert r2.tags == []

    def test_upstream_accepts_vless(self):
        vless = VlessConfig(uuid="u", server="s")
        cfg = RelayConfig(name="r", upstream=vless)
        assert cfg.upstream is vless

    def test_upstream_accepts_shadowsocks(self):
        ss = ShadowsocksConfig(server="s", port=80, password="p")
        cfg = RelayConfig(name="r", upstream=ss)
        assert cfg.upstream is ss

    def test_upstream_accepts_none_explicitly(self):
        cfg = RelayConfig(name="r", upstream=None)
        assert cfg.upstream is None


class TestRelayConfigSerialisation:
    def test_asdict_has_all_fields(self):
        cfg = RelayConfig(name="r")
        d = dataclasses.asdict(cfg)
        expected = {f.name for f in dataclasses.fields(RelayConfig)}
        assert set(d.keys()) == expected

    def test_asdict_roundtrip_no_upstream(self):
        original = RelayConfig(
            name="hop1",
            listen_address="0.0.0.0",
            listen_port=9090,
            tags=["fast", "eu"],
        )
        restored = RelayConfig(**dataclasses.asdict(original))
        assert restored == original

    def test_asdict_with_vless_upstream_becomes_dict(self):
        vless = VlessConfig(uuid="abc-123", server="vpn.example.com", port=8443)
        cfg = RelayConfig(name="hop1", upstream=vless)
        d = dataclasses.asdict(cfg)
        assert isinstance(d["upstream"], dict)
        assert d["upstream"]["uuid"] == "abc-123"
        assert d["upstream"]["server"] == "vpn.example.com"
        assert d["upstream"]["port"] == 8443

    def test_asdict_with_shadowsocks_upstream_becomes_dict(self):
        ss = ShadowsocksConfig(server="ss.example.com", port=8388, password="secret")
        cfg = RelayConfig(name="hop1", upstream=ss)
        d = dataclasses.asdict(cfg)
        assert isinstance(d["upstream"], dict)
        assert d["upstream"]["server"] == "ss.example.com"
        assert d["upstream"]["password"] == "secret"

    def test_asdict_tags_are_independent(self):
        cfg = RelayConfig(name="r", tags=["a", "b"])
        d = dataclasses.asdict(cfg)
        d["tags"].append("c")
        assert cfg.tags == ["a", "b"]

    def test_asdict_upstream_none_serialises_as_none(self):
        cfg = RelayConfig(name="r", upstream=None)
        d = dataclasses.asdict(cfg)
        assert d["upstream"] is None
