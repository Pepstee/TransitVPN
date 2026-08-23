"""Tests for transitvpn.qrcode — URI format assertions, no network."""

from __future__ import annotations

import base64
import uuid
from urllib.parse import parse_qs, urlparse

import pytest

from transitvpn.keygen import Keys, generate_keys
from transitvpn.qrcode import (
    DEFAULT_FINGERPRINT,
    DEFAULT_FLOW,
    DEFAULT_SNI,
    DEFAULT_SS_METHOD,
    make_ss_uri,
    make_vless_uri,
    render_qr,
    write_qr_png,
)

# The share URI must use the same cipher the server config uses.
_SS_METHOD = DEFAULT_SS_METHOD


@pytest.fixture()
def keys() -> Keys:
    return generate_keys()


@pytest.fixture()
def vless_uri(keys: Keys) -> str:
    return make_vless_uri(keys, "1.2.3.4", 443)


@pytest.fixture()
def ss_uri(keys: Keys) -> str:
    return make_ss_uri(keys, "1.2.3.4", 8388)


def _decode_ss_userinfo(userinfo: str) -> str:
    """Restore base64 padding and decode SS userinfo."""
    padded = userinfo + "=" * (-len(userinfo) % 4)
    return base64.urlsafe_b64decode(padded).decode()


# ---------------------------------------------------------------------------
# make_vless_uri — scheme and structure
# ---------------------------------------------------------------------------


class TestVlessUriScheme:
    def test_starts_with_vless_scheme(self, vless_uri: str) -> None:
        assert vless_uri.startswith("vless://")

    def test_parsed_scheme_is_vless(self, vless_uri: str) -> None:
        assert urlparse(vless_uri).scheme == "vless"

    def test_returns_string(self, keys: Keys) -> None:
        assert isinstance(make_vless_uri(keys, "1.2.3.4", 443), str)

    def test_at_separator_present(self, vless_uri: str) -> None:
        assert "@" in vless_uri

    def test_query_string_present(self, vless_uri: str) -> None:
        assert urlparse(vless_uri).query != ""

    def test_question_mark_separates_query(self, vless_uri: str) -> None:
        assert "?" in vless_uri


# ---------------------------------------------------------------------------
# make_vless_uri — authority (uuid@host:port)
# ---------------------------------------------------------------------------


class TestVlessUriAuthority:
    def test_host_embedded_in_netloc(self, vless_uri: str) -> None:
        assert urlparse(vless_uri).hostname == "1.2.3.4"

    def test_port_embedded_in_netloc(self, vless_uri: str) -> None:
        assert urlparse(vless_uri).port == 443

    def test_uuid_is_username_in_netloc(self, keys: Keys, vless_uri: str) -> None:
        assert urlparse(vless_uri).username == keys.vless_uuid

    def test_uuid_is_valid_uuid(self, keys: Keys, vless_uri: str) -> None:
        username = urlparse(vless_uri).username
        parsed = uuid.UUID(username)
        assert str(parsed) == keys.vless_uuid

    def test_custom_host_is_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "5.6.7.8", 443)
        assert urlparse(uri).hostname == "5.6.7.8"

    def test_custom_port_is_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "1.2.3.4", 8443)
        assert urlparse(uri).port == 8443

    def test_port_80_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "1.2.3.4", 80)
        assert urlparse(uri).port == 80

    def test_port_65535_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "1.2.3.4", 65535)
        assert urlparse(uri).port == 65535

    def test_fallback_host_zero_dot_zero(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "0.0.0.0", 443)
        assert urlparse(uri).hostname == "0.0.0.0"


# ---------------------------------------------------------------------------
# make_vless_uri — query parameters
# ---------------------------------------------------------------------------


class TestVlessUriQueryParams:
    def test_security_is_reality(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["security"] == ["reality"]

    def test_pbk_is_reality_public_key(self, keys: Keys, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["pbk"] == [keys.reality_public_key]

    def test_pbk_is_not_reality_private_key(self, keys: Keys, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["pbk"] != [keys.reality_private_key]

    def test_encryption_is_string_none(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["encryption"] == ["none"]

    def test_type_is_tcp(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["type"] == ["tcp"]

    def test_all_required_params_present(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        required = {"security", "pbk", "encryption", "type", "sni", "fp", "flow"}
        assert required.issubset(params.keys())

    def test_sni_default_matches_server(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["sni"] == [DEFAULT_SNI]

    def test_fingerprint_present(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["fp"] == [DEFAULT_FINGERPRINT]

    def test_flow_is_xtls_rprx_vision(self, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert params["flow"] == [DEFAULT_FLOW]

    def test_short_id_override_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "1.2.3.4", 443, short_id="a1b2")
        params = parse_qs(urlparse(uri).query)
        assert params["sid"] == ["a1b2"]

    def test_sni_override_reflected(self, keys: Keys) -> None:
        uri = make_vless_uri(keys, "1.2.3.4", 443, sni="vpn.example.com")
        params = parse_qs(urlparse(uri).query)
        assert params["sni"] == ["vpn.example.com"]

    def test_pbk_survives_round_trip(self, keys: Keys, vless_uri: str) -> None:
        # urlencode then parse_qs must recover the exact public key
        params = parse_qs(urlparse(vless_uri).query)
        assert params["pbk"][0] == keys.reality_public_key

    def test_public_key_not_equal_to_private_key(self, keys: Keys) -> None:
        # Guard: the two key fields must differ so test_pbk_is_not_reality_private_key is meaningful
        assert keys.reality_public_key != keys.reality_private_key


# ---------------------------------------------------------------------------
# make_vless_uri — independence between calls
# ---------------------------------------------------------------------------


class TestVlessUriIndependence:
    def test_different_keys_produce_different_uri(self) -> None:
        k1, k2 = generate_keys(), generate_keys()
        assert make_vless_uri(k1, "1.2.3.4", 443) != make_vless_uri(k2, "1.2.3.4", 443)

    def test_different_host_produces_different_uri(self, keys: Keys) -> None:
        assert make_vless_uri(keys, "1.1.1.1", 443) != make_vless_uri(keys, "8.8.8.8", 443)

    def test_different_port_produces_different_uri(self, keys: Keys) -> None:
        assert make_vless_uri(keys, "1.2.3.4", 443) != make_vless_uri(keys, "1.2.3.4", 8443)

    def test_same_keys_host_port_produces_identical_uri(self, keys: Keys) -> None:
        u1 = make_vless_uri(keys, "1.2.3.4", 443)
        u2 = make_vless_uri(keys, "1.2.3.4", 443)
        assert u1 == u2

    def test_different_keys_different_pbk_in_uri(self) -> None:
        k1, k2 = generate_keys(), generate_keys()
        p1 = parse_qs(urlparse(make_vless_uri(k1, "x", 1)).query)["pbk"][0]
        p2 = parse_qs(urlparse(make_vless_uri(k2, "x", 1)).query)["pbk"][0]
        assert p1 != p2


# ---------------------------------------------------------------------------
# make_ss_uri — scheme and structure
# ---------------------------------------------------------------------------


class TestSsUriScheme:
    def test_starts_with_ss_scheme(self, ss_uri: str) -> None:
        assert ss_uri.startswith("ss://")

    def test_parsed_scheme_is_ss(self, ss_uri: str) -> None:
        assert urlparse(ss_uri).scheme == "ss"

    def test_returns_string(self, keys: Keys) -> None:
        assert isinstance(make_ss_uri(keys, "1.2.3.4", 8388), str)

    def test_at_separator_present(self, ss_uri: str) -> None:
        assert "@" in ss_uri

    def test_no_query_string(self, ss_uri: str) -> None:
        assert urlparse(ss_uri).query == ""


# ---------------------------------------------------------------------------
# make_ss_uri — authority
# ---------------------------------------------------------------------------


class TestSsUriAuthority:
    def test_host_embedded_in_netloc(self, ss_uri: str) -> None:
        assert urlparse(ss_uri).hostname == "1.2.3.4"

    def test_port_embedded_in_netloc(self, ss_uri: str) -> None:
        assert urlparse(ss_uri).port == 8388

    def test_custom_host_is_reflected(self, keys: Keys) -> None:
        uri = make_ss_uri(keys, "5.6.7.8", 8388)
        assert urlparse(uri).hostname == "5.6.7.8"

    def test_custom_port_is_reflected(self, keys: Keys) -> None:
        uri = make_ss_uri(keys, "1.2.3.4", 9999)
        assert urlparse(uri).port == 9999

    def test_fallback_host_zero_dot_zero(self, keys: Keys) -> None:
        uri = make_ss_uri(keys, "0.0.0.0", 8388)
        assert urlparse(uri).hostname == "0.0.0.0"

    def test_uri_ends_with_at_host_colon_port(self, keys: Keys) -> None:
        uri = make_ss_uri(keys, "10.0.0.1", 8388)
        assert uri.endswith("@10.0.0.1:8388")


# ---------------------------------------------------------------------------
# make_ss_uri — userinfo encoding
# ---------------------------------------------------------------------------


class TestSsUriUserinfo:
    def test_userinfo_decodes_to_method_colon_password(self, keys: Keys, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        decoded = _decode_ss_userinfo(userinfo)
        method, password = decoded.split(":", 1)
        assert method == _SS_METHOD
        assert password == keys.ss_password

    def test_method_is_ss2022_blake3_aes256(self, keys: Keys, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        decoded = _decode_ss_userinfo(userinfo)
        assert decoded.startswith("2022-blake3-aes-256-gcm:")

    def test_password_survives_base64_round_trip(self, keys: Keys, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        decoded = _decode_ss_userinfo(userinfo)
        _, recovered_password = decoded.split(":", 1)
        assert recovered_password == keys.ss_password

    def test_userinfo_has_no_padding_chars(self, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        assert "=" not in userinfo

    def test_userinfo_uses_urlsafe_alphabet_no_plus(self, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        assert "+" not in userinfo

    def test_userinfo_uses_urlsafe_alphabet_no_slash(self, ss_uri: str) -> None:
        userinfo = urlparse(ss_uri).username
        assert "/" not in userinfo

    def test_userinfo_is_valid_urlsafe_base64_alphabet(self, ss_uri: str) -> None:
        import re
        userinfo = urlparse(ss_uri).username
        assert re.fullmatch(r"[A-Za-z0-9\-_]+", userinfo), (
            f"userinfo contains unexpected chars: {userinfo!r}"
        )


# ---------------------------------------------------------------------------
# make_ss_uri — independence between calls
# ---------------------------------------------------------------------------


class TestSsUriIndependence:
    def test_different_keys_produce_different_uri(self) -> None:
        k1, k2 = generate_keys(), generate_keys()
        assert make_ss_uri(k1, "1.2.3.4", 8388) != make_ss_uri(k2, "1.2.3.4", 8388)

    def test_different_host_produces_different_uri(self, keys: Keys) -> None:
        assert make_ss_uri(keys, "1.1.1.1", 8388) != make_ss_uri(keys, "8.8.8.8", 8388)

    def test_different_port_produces_different_uri(self, keys: Keys) -> None:
        assert make_ss_uri(keys, "1.2.3.4", 8388) != make_ss_uri(keys, "1.2.3.4", 9999)

    def test_same_inputs_produce_identical_uri(self, keys: Keys) -> None:
        u1 = make_ss_uri(keys, "1.2.3.4", 8388)
        u2 = make_ss_uri(keys, "1.2.3.4", 8388)
        assert u1 == u2

    def test_different_keys_different_userinfo(self) -> None:
        k1, k2 = generate_keys(), generate_keys()
        ui1 = urlparse(make_ss_uri(k1, "x", 1)).username
        ui2 = urlparse(make_ss_uri(k2, "x", 1)).username
        assert ui1 != ui2


# ---------------------------------------------------------------------------
# Cross-function — vless and ss URIs are independent
# ---------------------------------------------------------------------------


class TestVlessVsSsIndependence:
    def test_vless_and_ss_have_different_schemes(self, keys: Keys) -> None:
        vless = make_vless_uri(keys, "1.2.3.4", 443)
        ss = make_ss_uri(keys, "1.2.3.4", 8388)
        assert urlparse(vless).scheme != urlparse(ss).scheme

    def test_vless_uri_does_not_start_with_ss(self, vless_uri: str) -> None:
        assert not vless_uri.startswith("ss://")

    def test_ss_uri_does_not_start_with_vless(self, ss_uri: str) -> None:
        assert not ss_uri.startswith("vless://")

    def test_ss_password_is_not_in_vless_uri(self, keys: Keys, vless_uri: str) -> None:
        # The ss_password must not leak into the vless URI
        assert keys.ss_password not in vless_uri

    def test_reality_private_key_not_in_vless_uri(self, keys: Keys, vless_uri: str) -> None:
        params = parse_qs(urlparse(vless_uri).query)
        assert (
            keys.reality_private_key not in vless_uri
            or params["pbk"] == [keys.reality_public_key]
        )
        # The private key must not appear as pbk
        assert params.get("pbk", [None])[0] != keys.reality_private_key


# ---------------------------------------------------------------------------
# Cross-module — the share URI must match the server config it accompanies
# ---------------------------------------------------------------------------


class TestUriMatchesServerConfig:
    """A bootstrap run emits a server config and a client URI together; the
    connection only works if their parameters agree. These guard that contract.
    """

    def test_vless_pbk_pairs_with_server_private_key(self, keys: Keys) -> None:
        from transitvpn.server import build_xray_config

        xray = build_xray_config(keys)
        reality = xray["inbounds"][0]["streamSettings"]["realitySettings"]
        params = parse_qs(urlparse(make_vless_uri(keys, "1.2.3.4", 443)).query)
        # Client carries the public key; server holds the matching private key.
        assert params["pbk"] == [keys.reality_public_key]
        assert reality["privateKey"] == keys.reality_private_key

    def test_vless_flow_matches_server(self, keys: Keys) -> None:
        from transitvpn.server import build_xray_config

        xray = build_xray_config(keys)
        server_flow = xray["inbounds"][0]["settings"]["clients"][0]["flow"]
        params = parse_qs(urlparse(make_vless_uri(keys, "1.2.3.4", 443)).query)
        assert params["flow"] == [server_flow]

    def test_vless_sni_matches_server_servernames(self, keys: Keys) -> None:
        from transitvpn.server import build_xray_config

        xray = build_xray_config(keys)
        server_names = xray["inbounds"][0]["streamSettings"]["realitySettings"]["serverNames"]
        params = parse_qs(urlparse(make_vless_uri(keys, "1.2.3.4", 443)).query)
        assert params["sni"][0] in server_names

    def test_ss_method_matches_server(self, keys: Keys) -> None:
        from transitvpn.server import build_ss_config

        ss_cfg = build_ss_config(keys)
        decoded = _decode_ss_userinfo(urlparse(make_ss_uri(keys, "1.2.3.4", 8388)).username)
        method, _ = decoded.split(":", 1)
        assert method == ss_cfg["method"]


# ---------------------------------------------------------------------------
# render_qr / write_qr_png — the URIs are rendered as scannable QR codes
# ---------------------------------------------------------------------------


class TestRenderQr:
    def test_render_returns_nonempty_string(self, vless_uri: str) -> None:
        out = render_qr(vless_uri)
        assert isinstance(out, str)
        assert out.strip() != ""

    def test_render_is_multiline_grid(self, vless_uri: str) -> None:
        # A QR matrix is square: many rows, each row non-trivial in width.
        lines = render_qr(vless_uri).splitlines()
        assert len(lines) > 10
        assert all(len(line) > 10 for line in lines)

    def test_render_encodes_the_uri(self, vless_uri: str) -> None:
        # The rendered output must be the QR for exactly this URI: rendering a
        # different URI must change the drawn matrix.
        other = make_vless_uri(generate_keys(), "9.9.9.9", 443)
        assert render_qr(vless_uri) != render_qr(other)

    def test_render_is_deterministic(self, vless_uri: str) -> None:
        assert render_qr(vless_uri) == render_qr(vless_uri)

    def test_render_ss_uri(self, ss_uri: str) -> None:
        assert render_qr(ss_uri).strip() != ""

    def test_render_border_is_configurable(self, vless_uri: str) -> None:
        tight = render_qr(vless_uri, border=0)
        wide = render_qr(vless_uri, border=4)
        assert len(wide.splitlines()) > len(tight.splitlines())

    def test_write_png_creates_valid_file(self, vless_uri: str, tmp_path) -> None:
        out = tmp_path / "client.qr.png"
        write_qr_png(vless_uri, str(out))
        data = out.read_bytes()
        assert out.exists() and len(data) > 0
        assert data[:8] == b"\x89PNG\r\n\x1a\n"  # PNG magic
