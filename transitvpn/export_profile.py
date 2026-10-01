"""Secret-safe export of the generated single-peer VLESS+REALITY profile."""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import uuid
from pathlib import Path
from typing import Any, NoReturn

from transitvpn.qrcode import make_vless_uri_from_fields

_MAX_INPUT_BYTES = 1024 * 1024
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_SHORT_ID = re.compile(r"(?:[0-9a-f]{2}){1,8}\Z")
_SUPPORTED_FLOW = "xtls-rprx-vision"


class ProfileExportError(ValueError):
    """A fixed-message refusal that never includes profile values or paths."""

    def __init__(self) -> None:
        super().__init__("client profile export refused")


def _reject() -> NoReturn:
    raise ProfileExportError() from None


def _mapping(
    value: Any,
    required: set[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject()
    keys = set(value)
    if not required.issubset(keys) or keys - required - optional:
        _reject()
    return value


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        _reject()
    return value


def _host(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 254:
        _reject()
    if any(ord(char) < 33 or ord(char) == 127 for char in value):
        _reject()
    if any(char in "/?#@%\\[]|<>" for char in value):
        _reject()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if ":" in value:
        _reject()
    name = value.removesuffix(".")
    if not name or len(name) > 253:
        _reject()
    if any(not _DNS_LABEL.fullmatch(label.lower()) for label in name.split(".")):
        _reject()
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def build_profile_uri(config: dict[str, Any]) -> str:
    """Convert one supported generated VLESS RAW/TCP REALITY config to a URI."""
    root = _mapping(config, {"outbounds"}, {"log", "inbounds"})
    if "log" in root:
        log = _mapping(root["log"], {"loglevel"})
        level = log["loglevel"]
        if not isinstance(level, str) or level not in {
            "none", "error", "warning", "info", "debug"
        }:
            _reject()

    if "inbounds" in root:
        inbounds = root["inbounds"]
        if not isinstance(inbounds, list) or len(inbounds) != 1:
            _reject()
        inbound = _mapping(
            inbounds[0], {"listen", "port", "protocol", "settings", "tag"}
        )
        inbound_settings = _mapping(inbound["settings"], {"udp"})
        _port(inbound["port"])
        if (
            inbound["listen"] != "127.0.0.1"
            or inbound["protocol"] != "socks"
            or inbound["tag"] != "socks"
            or inbound_settings["udp"] is not True
        ):
            _reject()

    outbounds = root["outbounds"]
    if not isinstance(outbounds, list) or len(outbounds) != 1:
        _reject()
    outbound = _mapping(
        outbounds[0], {"protocol", "tag", "settings", "streamSettings"}
    )
    if outbound["protocol"] != "vless" or outbound["tag"] != "proxy":
        _reject()

    settings = _mapping(outbound["settings"], {"vnext"})
    peers = settings["vnext"]
    if not isinstance(peers, list) or len(peers) != 1:
        _reject()
    peer = _mapping(peers[0], {"address", "port", "users"})
    host, port = _host(peer["address"]), _port(peer["port"])
    users = peer["users"]
    if not isinstance(users, list) or len(users) != 1:
        _reject()
    user = _mapping(users[0], {"id", "encryption"}, {"flow"})
    if not isinstance(user["id"], str) or user["encryption"] != "none":
        _reject()
    try:
        user_id = str(uuid.UUID(user["id"]))
    except (ValueError, TypeError, AttributeError):
        _reject()
    flow = user.get("flow", "")
    if not isinstance(flow, str) or flow not in {"", _SUPPORTED_FLOW}:
        _reject()

    stream = _mapping(
        outbound["streamSettings"], {"network", "security", "realitySettings"}
    )
    network = stream["network"]
    if (
        not isinstance(network, str)
        or network not in {"raw", "tcp"}
        or stream["security"] != "reality"
    ):
        _reject()
    reality = _mapping(
        stream["realitySettings"],
        {"serverName", "fingerprint", "shortId"},
        {"publicKey", "password"},
    )
    aliases: list[str] = []
    for name in ("publicKey", "password"):
        if name in reality:
            value = reality[name]
            if not isinstance(value, str) or not value:
                _reject()
            aliases.append(value)
    if not aliases or any(value != aliases[0] for value in aliases[1:]):
        _reject()

    server_name = reality["serverName"]
    fingerprint = reality["fingerprint"]
    short_id = reality["shortId"]
    if not isinstance(server_name, str) or not server_name:
        _reject()
    if not isinstance(fingerprint, str) or not fingerprint:
        _reject()
    if not isinstance(short_id, str) or not _SHORT_ID.fullmatch(short_id):
        _reject()

    return make_vless_uri_from_fields(
        user_id,
        aliases[0],
        host,
        port,
        sni=server_name,
        short_id=short_id,
        fingerprint=fingerprint,
        flow=flow or None,
    )


def _read_config(path: Path) -> Any:
    fd: int | None = None
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_INPUT_BYTES:
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
            payload = source.read(_MAX_INPUT_BYTES + 1)
        if len(payload) > _MAX_INPUT_BYTES:
            _reject()
        return json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object)
    except ProfileExportError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, RecursionError):
        _reject()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _ensure_private_parent(path: Path) -> None:
    parent = path.parent
    created = False
    try:
        info = parent.lstat()
    except FileNotFoundError:
        try:
            parent.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode):
        _reject()
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o077 or mode & 0o300 != 0o300:
        _reject()
    if created and mode & 0o777 != 0o700:
        _reject()


def _remove_partial(path: Path, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
            path.unlink()
    except OSError:
        pass


def _write_new_profile(path: Path, uri: str) -> None:
    _ensure_private_parent(path)
    fd: int | None = None
    identity: os.stat_result | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        identity = os.fstat(fd)
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            raise OSError()
        os.fchmod(fd, 0o600)
        remaining = memoryview((uri + "\n").encode("utf-8"))
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
    except (OSError, UnicodeError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        _remove_partial(path, identity)
        _reject()


def export_profile(input_path: Path, output_path: Path) -> None:
    """Write one new private share file; never print profile data or paths."""
    try:
        uri = build_profile_uri(_read_config(Path(input_path)))
        _write_new_profile(Path(output_path), uri)
    except ProfileExportError:
        raise
    except (
        OSError, UnicodeError, TypeError, ValueError, KeyError,
        IndexError, AttributeError, RecursionError,
    ):
        _reject()
