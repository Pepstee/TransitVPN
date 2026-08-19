"""Generate server-side config dicts for Xray (VLESS+REALITY) and Shadowsocks-2022."""

from __future__ import annotations

from typing import Any

from transitvpn.keygen import Keys


def build_xray_config(
    keys: Keys,
    *,
    port: int = 443,
    dest: str = "www.microsoft.com:443",
    server_names: list[str] | None = None,
    short_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Return an Xray server config dict for VLESS+REALITY."""
    if server_names is None:
        server_names = ["www.microsoft.com"]
    if short_ids is None:
        short_ids = [""]
    return {
        "inbounds": [
            {
                "port": port,
                "protocol": "vless",
                "settings": {
                    "clients": [
                        {
                            "id": keys.vless_uuid,
                            "flow": "xtls-rprx-vision",
                        }
                    ],
                    "decryption": "none",
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": dest,
                        "xver": 0,
                        "serverNames": server_names,
                        "privateKey": keys.reality_private_key,
                        "shortIds": short_ids,
                    },
                },
            }
        ],
        "outbounds": [
            {
                "protocol": "freedom",
                "tag": "direct",
            }
        ],
    }


def build_ss_config(
    keys: Keys,
    *,
    server: str = "0.0.0.0",
    port: int = 8388,
    method: str = "2022-blake3-aes-256-gcm",
) -> dict[str, Any]:
    """Return a Shadowsocks-2022 server config dict."""
    return {
        "server": server,
        "server_port": port,
        "password": keys.ss_password,
        "method": method,
        "mode": "tcp_and_udp",
    }
