"""Configuration dataclasses for transitvpn protocols."""

from __future__ import annotations

from dataclasses import dataclass, field


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
