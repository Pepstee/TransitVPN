"""Configuration dataclasses for transitvpn protocols."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from transitvpn.keygen import Keys


_SHORT_ID = re.compile(r"^(?:[0-9a-f]{2}){1,8}$")


@dataclass
class VlessConfig:
    """VLESS protocol configuration."""

    uuid: str
    server: str
    port: int = 443
    flow: str = ""
    network: str = "tcp"
    tls: bool = True
    sni: str = ""
    fingerprint: str = "chrome"
    public_key: str = ""
    short_id: str = ""
    path: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.uuid:
            raise ValueError("uuid must not be empty")
        if not self.server:
            raise ValueError("server must not be empty")
        if not (0 < self.port < 65536):
            raise ValueError(f"port out of range: {self.port}")


@dataclass
class ShadowsocksConfig:
    """Shadowsocks protocol configuration."""

    server: str
    port: int
    password: str
    method: str = "aes-256-gcm"
    plugin: str = ""
    plugin_opts: str = ""

    def __post_init__(self) -> None:
        if not self.server:
            raise ValueError("server must not be empty")
        if not (0 < self.port < 65536):
            raise ValueError(f"port out of range: {self.port}")
        if not self.password:
            raise ValueError("password must not be empty")
        if self.method not in self._SUPPORTED_METHODS:
            raise ValueError(
                f"unsupported method: {self.method!r} "
                f"(supported: {', '.join(sorted(self._SUPPORTED_METHODS))})"
            )

    _SUPPORTED_METHODS = frozenset(
        {
            "aes-128-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "xchacha20-ietf-poly1305",
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        }
    )


@dataclass
class RelayConfig:
    """Relay / tunnel hop configuration linking two protocol endpoints."""

    name: str
    listen_address: str = "127.0.0.1"
    listen_port: int = 10808
    upstream: VlessConfig | ShadowsocksConfig | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("name must not be empty")
        if not (0 < self.listen_port < 65536):
            raise ValueError(f"listen_port out of range: {self.listen_port}")


@dataclass(frozen=True)
class XrayDeployment:
    """Single source of truth for matching VLESS+REALITY peers."""

    keys: Keys
    server: str
    target: str
    server_name: str
    short_id: str
    target_verified: bool
    port: int = 443
    socks_port: int = 10808
    fingerprint: str = "chrome"

    def __post_init__(self) -> None:
        if not self.server or not self.server_name:
            raise ValueError("server and server_name must not be empty")
        if not self.target_verified:
            raise ValueError("REALITY target must be deliberately verified")
        host, separator, port = self.target.rpartition(":")
        if not separator or not host or not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError("target must be HOST:PORT")
        if not _SHORT_ID.fullmatch(self.short_id):
            raise ValueError(
                "short_id must be 2-16 lowercase hexadecimal characters with even length"
            )
        if not 0 < self.port < 65536 or not 0 < self.socks_port < 65536:
            raise ValueError("ports must be between 1 and 65535")
