"""Secret-safe import of an exported VLESS+REALITY client profile."""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qsl, urlsplit

from transitvpn.export_profile import (
    _SHORT_ID,
    _SUPPORTED_FLOW,
    ProfileExportError,
    _ensure_private_parent,
    _host,
    _remove_partial,
)
from transitvpn.xray import validate_configs

_MAX_PROFILE_BYTES = 8192
_DEFAULT_SOCKS_PORT = 10808
_FIXED_QUERY = {"security": "reality", "encryption": "none", "type": "tcp"}
_REQUIRED_QUERY = frozenset(_FIXED_QUERY) | {"pbk", "sni", "sid", "fp"}
_ALLOWED_QUERY = _REQUIRED_QUERY | {"flow"}
_PUBLIC_KEY = re.compile(r"[A-Za-z0-9_-]{43}")
_FINGERPRINT = re.compile(r"[a-z0-9]{1,32}")
_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")


class ProfileImportError(ValueError):
    """A fixed-message refusal that never includes profile values or paths."""

    def __init__(self) -> None:
        super().__init__("client profile import refused")


def _reject() -> NoReturn:
    raise ProfileImportError() from None


def parse_profile_uri(uri: str) -> dict[str, Any]:
    """Strictly parse the one supported VLESS RAW/TCP REALITY share URI."""
    if not isinstance(uri, str):
        _reject()
    try:
        parts = urlsplit(uri)
        port = parts.port
    except ValueError:
        _reject()
    if (
        parts.scheme != "vless"
        or parts.username is None
        or parts.password is not None
        or parts.hostname is None
        or parts.path != ""
        or parts.fragment != ""
        or parts.query == ""
        or port is None
        or not 1 <= port <= 65535
    ):
        _reject()
    try:
        user_id = str(uuid.UUID(parts.username))
    except (ValueError, TypeError, AttributeError):
        _reject()
    if user_id != parts.username:
        _reject()
    try:
        host = _host(parts.hostname)
    except ProfileExportError:
        _reject()
    try:
        pairs = parse_qsl(parts.query, strict_parsing=True, keep_blank_values=True)
    except ValueError:
        _reject()
    values: dict[str, str] = {}
    for key, value in pairs:
        if key in values or key not in _ALLOWED_QUERY:
            _reject()
        values[key] = value
    if not _REQUIRED_QUERY.issubset(values):
        _reject()
    for key, expected in _FIXED_QUERY.items():
        if values[key] != expected:
            _reject()
    public_key = values["pbk"]
    if not _PUBLIC_KEY.fullmatch(public_key):
        _reject()
    try:
        decoded_key = base64.b64decode(
            public_key + "=" * (-len(public_key) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError):
        _reject()
    if len(decoded_key) != 32:
        _reject()
    try:
        server_name = _host(values["sni"])
    except ProfileExportError:
        _reject()
    fingerprint = values["fp"]
    short_id = values["sid"]
    if not _FINGERPRINT.fullmatch(fingerprint):
        _reject()
    if not isinstance(short_id, str) or not _SHORT_ID.fullmatch(short_id):
        _reject()
    flow = values.get("flow", "")
    if flow not in ("", _SUPPORTED_FLOW):
        _reject()
    return {
        "uuid": user_id,
        "host": host,
        "port": port,
        "public_key": public_key,
        "server_name": server_name,
        "fingerprint": fingerprint,
        "short_id": short_id,
        "flow": flow,
    }


def build_client_config(
    fields: dict[str, Any], *, socks_port: int = _DEFAULT_SOCKS_PORT
) -> dict[str, Any]:
    """Build the managed client config from strictly parsed profile fields."""
    if (
        isinstance(socks_port, bool)
        or not isinstance(socks_port, int)
        or not 1 <= socks_port <= 65535
    ):
        _reject()
    user: dict[str, Any] = {"id": fields["uuid"], "encryption": "none"}
    if fields["flow"]:
        user["flow"] = fields["flow"]
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"udp": True},
            "tag": "socks",
        }],
        "outbounds": [{
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{
                "address": fields["host"],
                "port": fields["port"],
                "users": [user],
            }]},
            "streamSettings": {
                "network": "raw",
                "security": "reality",
                "realitySettings": {
                    "serverName": fields["server_name"],
                    "fingerprint": fields["fingerprint"],
                    "publicKey": fields["public_key"],
                    "shortId": fields["short_id"],
                },
            },
        }],
    }


def _read_profile(path: Path) -> str:
    fd: int | None = None
    text = ""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_PROFILE_BYTES:
            _reject()
        if stat.S_IMODE(before.st_mode) & 0o077:
            _reject()
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or stat.S_IMODE(opened.st_mode) & 0o077
        ):
            _reject()
        with os.fdopen(fd, "rb") as source:
            fd = None
            payload = source.read(_MAX_PROFILE_BYTES + 1)
        if len(payload) > _MAX_PROFILE_BYTES:
            _reject()
        text = payload.decode("utf-8")
    except ProfileImportError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError):
        _reject()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
    text = text.removesuffix("\n")
    if not text or _CONTROL_OR_SPACE.search(text):
        _reject()
    return text


def _write_new_config(path: Path, config: dict[str, Any]) -> None:
    try:
        _ensure_private_parent(path)
    except ProfileExportError:
        _reject()
    fd: int | None = None
    identity: os.stat_result | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        identity = os.fstat(fd)
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            raise OSError()
        os.fchmod(fd, 0o600)
        remaining = memoryview((json.dumps(config, indent=2) + "\n").encode("utf-8"))
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError()
            remaining = remaining[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        directory_fd = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, TypeError, ValueError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        _remove_partial(path, identity)
        _reject()


def import_profile(
    input_path: Path,
    output_path: Path,
    *,
    socks_port: int = _DEFAULT_SOCKS_PORT,
    xray_binary: str = "xray",
) -> None:
    """Validate one exported profile and write the managed client config privately."""
    try:
        fields = parse_profile_uri(_read_profile(Path(input_path)))
        config = build_client_config(fields, socks_port=socks_port)
        try:
            validate_configs({"client": config}, xray_binary)
        except RuntimeError:
            _reject()
        _write_new_config(Path(output_path), config)
    except ProfileImportError:
        raise
    except (
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        KeyError,
        IndexError,
        AttributeError,
        RecursionError,
    ):
        _reject()
