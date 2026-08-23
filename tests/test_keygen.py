"""Adversarial tests for transitvpn/keygen.py — independent check, no mocking of unit under test."""

import base64
import re
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from transitvpn.keygen import Keys, generate_keys


def _b64d(s: str) -> bytes:
    """Decode unpadded base64url (Xray RawURLEncoding) by restoring padding."""
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


UUID_V4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


# ---------------------------------------------------------------------------
# Keys dataclass
# ---------------------------------------------------------------------------


class TestKeysDataclass:
    def test_all_fields_present(self):
        k = generate_keys()
        assert hasattr(k, "vless_uuid")
        assert hasattr(k, "reality_private_key")
        assert hasattr(k, "reality_public_key")
        assert hasattr(k, "ss_password")

    def test_all_fields_are_strings(self):
        k = generate_keys()
        assert isinstance(k.vless_uuid, str)
        assert isinstance(k.reality_private_key, str)
        assert isinstance(k.reality_public_key, str)
        assert isinstance(k.ss_password, str)

    def test_no_field_is_empty(self):
        k = generate_keys()
        assert k.vless_uuid
        assert k.reality_private_key
        assert k.reality_public_key
        assert k.ss_password

    def test_keys_is_dataclass_instance(self):
        k = generate_keys()
        assert isinstance(k, Keys)

    def test_dataclass_equality_by_value(self):
        k = Keys(
            vless_uuid="a",
            reality_private_key="b",
            reality_public_key="c",
            ss_password="d",
        )
        k2 = Keys(
            vless_uuid="a",
            reality_private_key="b",
            reality_public_key="c",
            ss_password="d",
        )
        assert k == k2

    def test_dataclass_inequality_when_field_differs(self):
        k = generate_keys()
        k2 = Keys(
            vless_uuid=k.vless_uuid,
            reality_private_key=k.reality_private_key,
            reality_public_key=k.reality_public_key,
            ss_password="different",
        )
        assert k != k2


# ---------------------------------------------------------------------------
# UUID v4
# ---------------------------------------------------------------------------


class TestVlessUuid:
    def test_uuid_v4_regex(self):
        k = generate_keys()
        assert UUID_V4_RE.match(k.vless_uuid), f"Not UUID v4: {k.vless_uuid!r}"

    def test_uuid_parseable(self):
        k = generate_keys()
        parsed = uuid.UUID(k.vless_uuid)
        assert str(parsed) == k.vless_uuid

    def test_uuid_version_is_4(self):
        k = generate_keys()
        assert uuid.UUID(k.vless_uuid).version == 4

    def test_uuid_variant_is_rfc4122(self):
        k = generate_keys()
        parsed = uuid.UUID(k.vless_uuid)
        # RFC 4122 variant: top two bits of clock_seq_hi_variant are 1,0
        assert parsed.variant == uuid.RFC_4122

    def test_uuid_has_correct_hyphen_positions(self):
        k = generate_keys()
        parts = k.vless_uuid.split("-")
        assert len(parts) == 5
        assert [len(p) for p in parts] == [8, 4, 4, 4, 12]

    def test_uuid_is_lowercase_hex(self):
        k = generate_keys()
        without_hyphens = k.vless_uuid.replace("-", "")
        assert without_hyphens == without_hyphens.lower()
        assert all(c in "0123456789abcdef" for c in without_hyphens)


# ---------------------------------------------------------------------------
# X25519 key lengths and encoding
# ---------------------------------------------------------------------------

X25519_RAW_BYTES = 32
# Xray REALITY keys are base64 RawURLEncoding (unpadded): 32 bytes -> 43 chars.
RAW_URLSAFE_B64_LEN = 43


class TestRealityPrivateKey:
    def test_length(self):
        k = generate_keys()
        assert len(k.reality_private_key) == RAW_URLSAFE_B64_LEN

    def test_is_unpadded(self):
        # Xray RawURLEncoding rejects '=' padding; the key must carry none.
        k = generate_keys()
        assert "=" not in k.reality_private_key

    def test_is_urlsafe_base64(self):
        k = generate_keys()
        # urlsafe base64 uses - and _ not + and /
        assert "+" not in k.reality_private_key
        assert "/" not in k.reality_private_key

    def test_decodes_to_32_bytes(self):
        k = generate_keys()
        raw = _b64d(k.reality_private_key)
        assert len(raw) == X25519_RAW_BYTES

    def test_decodable_without_error(self):
        k = generate_keys()
        _b64d(k.reality_private_key)  # must not raise

    def test_decoded_key_is_valid_x25519_private_key(self):
        k = generate_keys()
        raw = _b64d(k.reality_private_key)
        # If we can load it as an X25519 private key, it is valid
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        loaded = X25519PrivateKey.from_private_bytes(raw)
        assert loaded is not None


class TestRealityPublicKey:
    def test_length(self):
        k = generate_keys()
        assert len(k.reality_public_key) == RAW_URLSAFE_B64_LEN

    def test_is_unpadded(self):
        k = generate_keys()
        assert "=" not in k.reality_public_key

    def test_is_urlsafe_base64(self):
        k = generate_keys()
        assert "+" not in k.reality_public_key
        assert "/" not in k.reality_public_key

    def test_decodes_to_32_bytes(self):
        k = generate_keys()
        raw = _b64d(k.reality_public_key)
        assert len(raw) == X25519_RAW_BYTES

    def test_decodable_without_error(self):
        k = generate_keys()
        _b64d(k.reality_public_key)  # must not raise

    def test_public_key_matches_private_key(self):
        """The encoded public key must be derivable from the encoded private key."""
        k = generate_keys()
        priv_raw = _b64d(k.reality_private_key)
        pub_raw = _b64d(k.reality_public_key)

        loaded_priv = X25519PrivateKey.from_private_bytes(priv_raw)
        derived_pub_raw = loaded_priv.public_key().public_bytes_raw()
        assert derived_pub_raw == pub_raw

    def test_private_and_public_keys_differ(self):
        k = generate_keys()
        assert k.reality_private_key != k.reality_public_key


# ---------------------------------------------------------------------------
# Shadowsocks password
# ---------------------------------------------------------------------------

STANDARD_B64_LEN = 44  # base64.b64encode(32 bytes) = 44 chars


class TestSsPassword:
    def test_length(self):
        k = generate_keys()
        assert len(k.ss_password) == STANDARD_B64_LEN

    def test_is_standard_base64(self):
        k = generate_keys()
        # Standard base64 alphabet: A-Z a-z 0-9 + / and trailing =
        assert re.fullmatch(r"[A-Za-z0-9+/]+=?=?", k.ss_password), (
            f"Not standard base64: {k.ss_password!r}"
        )

    def test_decodes_to_32_bytes(self):
        k = generate_keys()
        raw = base64.b64decode(k.ss_password)
        assert len(raw) == 32

    def test_decodable_without_error(self):
        k = generate_keys()
        base64.b64decode(k.ss_password)  # must not raise


# ---------------------------------------------------------------------------
# Uniqueness across calls
# ---------------------------------------------------------------------------


class TestUniqueness:
    SAMPLE_SIZE = 20

    def _sample(self):
        return [generate_keys() for _ in range(self.SAMPLE_SIZE)]

    def test_vless_uuids_are_unique(self):
        samples = self._sample()
        uuids = [k.vless_uuid for k in samples]
        assert len(set(uuids)) == self.SAMPLE_SIZE

    def test_reality_private_keys_are_unique(self):
        samples = self._sample()
        keys = [k.reality_private_key for k in samples]
        assert len(set(keys)) == self.SAMPLE_SIZE

    def test_reality_public_keys_are_unique(self):
        samples = self._sample()
        keys = [k.reality_public_key for k in samples]
        assert len(set(keys)) == self.SAMPLE_SIZE

    def test_ss_passwords_are_unique(self):
        samples = self._sample()
        passwords = [k.ss_password for k in samples]
        assert len(set(passwords)) == self.SAMPLE_SIZE

    def test_consecutive_calls_differ(self):
        k1 = generate_keys()
        k2 = generate_keys()
        assert k1.vless_uuid != k2.vless_uuid
        assert k1.reality_private_key != k2.reality_private_key
        assert k1.reality_public_key != k2.reality_public_key
        assert k1.ss_password != k2.ss_password

    def test_private_and_public_keys_from_different_calls_are_unrelated(self):
        """k1's private key must NOT derive k2's public key."""
        k1 = generate_keys()
        k2 = generate_keys()
        priv_raw = _b64d(k1.reality_private_key)
        pub2_raw = _b64d(k2.reality_public_key)
        loaded_priv = X25519PrivateKey.from_private_bytes(priv_raw)
        derived = loaded_priv.public_key().public_bytes_raw()
        assert derived != pub2_raw
