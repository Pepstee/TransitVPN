"""Key generation for VPN protocol components."""

import base64
import os
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


@dataclass
class Keys:
    vless_uuid: str
    reality_private_key: str
    reality_public_key: str
    ss_password: str


def generate_keys() -> Keys:
    vless_uuid = str(uuid.uuid4())

    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    # Xray REALITY keys use base64 RawURLEncoding (URL-safe, NO padding), the
    # same form `xray x25519` emits. A trailing '=' is rejected by Xray's
    # config loader, so the padding must be stripped or the key cannot connect.
    reality_private_key = base64.urlsafe_b64encode(
        private_key.private_bytes_raw()
    ).decode().rstrip("=")
    reality_public_key = base64.urlsafe_b64encode(
        public_key.public_bytes_raw()
    ).decode().rstrip("=")

    ss_password = base64.b64encode(os.urandom(32)).decode()

    return Keys(
        vless_uuid=vless_uuid,
        reality_private_key=reality_private_key,
        reality_public_key=reality_public_key,
        ss_password=ss_password,
    )
