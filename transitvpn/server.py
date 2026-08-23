"""Generate matching current Xray VLESS+REALITY configurations."""

from __future__ import annotations

from typing import Any

from transitvpn.config import XrayDeployment
from transitvpn.keygen import Keys


def build_server_config(deployment: XrayDeployment) -> dict[str, Any]:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "port": deployment.port,
            "protocol": "vless",
            "settings": {"clients": [{"id": deployment.keys.vless_uuid,
                                        "flow": "xtls-rprx-vision"}],
                         "decryption": "none"},
            "streamSettings": {
                "network": "raw", "security": "reality",
                "realitySettings": {
                    "show": False, "target": deployment.target,
                    "serverNames": [deployment.server_name],
                    "privateKey": deployment.keys.reality_private_key,
                    "shortIds": [deployment.short_id],
                },
            },
        }],
        "outbounds": [{"protocol": "freedom", "tag": "direct"}],
    }


def build_client_config(deployment: XrayDeployment) -> dict[str, Any]:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": deployment.socks_port,
                      "protocol": "socks", "settings": {"udp": True}, "tag": "socks"}],
        "outbounds": [{
            "protocol": "vless", "tag": "proxy",
            "settings": {"vnext": [{"address": deployment.server, "port": deployment.port,
                                      "users": [{"id": deployment.keys.vless_uuid,
                                                 "encryption": "none",
                                                 "flow": "xtls-rprx-vision"}]}]},
            "streamSettings": {
                "network": "raw", "security": "reality",
                "realitySettings": {"serverName": deployment.server_name,
                                    "fingerprint": deployment.fingerprint,
                                    "publicKey": deployment.keys.reality_public_key,
                                    "shortId": deployment.short_id},
            },
        }],
    }


def build_xray_config(keys: Keys, **kwargs: Any) -> dict[str, Any]:
    """Compatibility wrapper; callers must now supply a verified target and short ID."""
    deployment = XrayDeployment(
        keys=keys, server=kwargs.pop("server", "127.0.0.1"),
        target=kwargs.pop("target", kwargs.pop("dest", "")),
        server_name=kwargs.pop("server_name", (kwargs.pop("server_names", [""]) or [""])[0]),
        short_id=kwargs.pop("short_id", (kwargs.pop("short_ids", [""]) or [""])[0]),
        target_verified=kwargs.pop("target_verified", False), port=kwargs.pop("port", 443),
    )
    if kwargs:
        raise TypeError(f"unexpected arguments: {', '.join(kwargs)}")
    return build_server_config(deployment)
