"""Create a small private, offline client recovery pack."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from transitvpn.export_profile import ProfileExportError, export_profile


class RecoveryPackError(ValueError):
    """A fixed-message refusal that never exposes profile data or paths."""

    def __init__(self) -> None:
        super().__init__("private recovery pack refused")


RECOVERY_GUIDE = """# TransitVPN offline client recovery pack

## What this pack contains

This directory contains exactly two files: `client.vless` (a private client
credential) and this static guide. It is client recovery material, not a server
backup, installer, or second endpoint. Keep the directory private (`0700`) and
both files private (`0600`). Never display, paste, or attach the profile.

## Supported Linux command-line route

The TransitVPN lifecycle commands below are supported on Linux. They require an
installed TransitVPN CLI and the pinned Xray **26.7.11** binary. Record the
trusted absolute Xray path before travel. In each shell, set:

```sh
PINNED_XRAY=/absolute/path/to/pinned/xray
export TRANSITVPN_XRAY_BIN="$PINNED_XRAY"
export TRANSITVPN_PROXY_BIN="$PINNED_XRAY"
```

`TRANSITVPN_XRAY_BIN` selects the binary used to validate an imported profile;
`TRANSITVPN_PROXY_BIN` selects the binary used by tunnel start and lifecycle
commands. These settings do not install either program.

Use an existing private client working directory. Before either import route,
run `down --client`; a missing config does not prove that no client process is
still running. If `down --client` refuses, preserve the state and diagnose it.

For a missing client config, import without `--replace`:

```sh
transitvpn down --client
transitvpn import-profile --input /absolute/private/pack/client.vless --xray-binary "$PINNED_XRAY" --socks-port 10808
```

The default import refuses to overwrite an existing config. To replace an
existing corrupt or intentionally refreshed config, first run
`transitvpn down --client`. Then use the explicit replacement option:

```sh
transitvpn down --client
transitvpn import-profile --input /absolute/private/pack/client.vless --xray-binary "$PINNED_XRAY" --socks-port 10808 --replace
```

Replacement refuses if `state/tunnel-client.pid` has any filesystem entry,
including a dangling symlink. Other state files are not blanket-refused. Do
not delete records or signal processes manually. Start and make one request to
a URL you have chosen and approved:

```sh
transitvpn up --client
transitvpn health --url https://USER_APPROVED_HOST/
```

To test recovery, stop and restart the client, then repeat the approved health
request:

```sh
transitvpn down --client
transitvpn up --client
transitvpn health --url https://USER_APPROVED_HOST/
```

`transitvpn status --client` reports process status only; it does not test
connectivity. `health` makes a real request through the configured SOCKS route
and does not use a direct fallback. It proves only that request, not global
DNS or routing. Reading this guide or exporting/importing a profile makes no
network request.

## Mac and phone

The TransitVPN command-line lifecycle is not supported on Mac or phones; its
safe process lifecycle requires Linux pidfd support. A separate route is a
compatible VLESS RAW/TCP REALITY app already installed on the device. The URI
does not carry custom DNS, routing, or app policy. Before trusting that app,
configure its fallback controls to disable direct/bypass fallback, then verify
the app's routing and failure behavior on the actual device and network before
travel. The app's profile import, traffic routing, DNS behavior, and
stop/restart recovery have not been verified on an actual Mac or phone; do not
assume system-wide protection.

## Handling and limits

Transfer and store this pack only through private channels. A profile remains
a reusable credential after import. If its identity is revoked or rotated,
do not restore this copy; request a newly issued profile. Changing the endpoint
or REALITY target requires a matching new profile. This pack creates no
recovery endpoint: that endpoint is unprovisioned. Public ingress, reachability
from other networks, global DNS protection, and Beijing access are unproven.
"""

_PACK_FILES = frozenset({"client.vless", "RECOVERY.txt"})


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _require_private_directory(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise RecoveryPackError()
    return info


def _require_private_file(path: Path) -> os.stat_result:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise RecoveryPackError()
    return info


def _remove_owned_file(path: Path, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if (
            _same_inode(current, identity)
            and stat.S_ISREG(current.st_mode)
            and current.st_nlink == 1
        ):
            path.unlink()
    except OSError:
        pass


def _remove_owned_directory(path: Path, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        current = path.lstat()
        if _same_inode(current, identity) and stat.S_ISDIR(current.st_mode):
            path.rmdir()
    except OSError:
        pass


def _sync_directory(path: Path, identity: os.stat_result) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or not _same_inode(opened, identity):
            raise OSError()
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_guide(path: Path, directory_identity: os.stat_result) -> os.stat_result:
    fd: int | None = None
    identity: os.stat_result | None = None
    try:
        _require_private_directory(path.parent)
        current_directory = path.parent.lstat()
        if not _same_inode(current_directory, directory_identity):
            raise OSError()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, 0o600)
        identity = os.fstat(fd)
        if not stat.S_ISREG(identity.st_mode) or identity.st_nlink != 1:
            raise OSError()
        os.fchmod(fd, 0o600)
        remaining = memoryview(RECOVERY_GUIDE.encode("utf-8"))
        while remaining:
            written = os.write(fd, remaining)
            if written <= 0:
                raise OSError()
            remaining = remaining[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        final = _require_private_file(path)
        if not _same_inode(final, identity):
            raise OSError()
        _sync_directory(path.parent, directory_identity)
        return final
    except (OSError, UnicodeError, RecoveryPackError):
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        _remove_owned_file(path, identity)
        raise RecoveryPackError() from None


def export_recovery_pack(client_config_path: Path, destination: Path) -> None:
    """Create a new directory containing the validated profile and static guide."""
    pack_dir = Path(destination)
    directory_identity: os.stat_result | None = None
    profile_identity: os.stat_result | None = None
    guide_identity: os.stat_result | None = None
    try:
        if not pack_dir.name or pack_dir.name in {".", ".."}:
            raise RecoveryPackError()
        parent_identity = _require_private_directory(pack_dir.parent)
        _ = parent_identity  # The parent is validated before creating the one new directory.
        try:
            pack_dir.lstat()
        except FileNotFoundError:
            pass
        else:
            raise RecoveryPackError()
        pack_dir.mkdir(mode=0o700)
        directory_identity = pack_dir.lstat()
        if (
            not stat.S_ISDIR(directory_identity.st_mode)
            or directory_identity.st_uid != os.geteuid()
            or stat.S_IMODE(directory_identity.st_mode) != 0o700
        ):
            raise RecoveryPackError()

        profile_path = pack_dir / "client.vless"
        try:
            export_profile(Path(client_config_path), profile_path)
        except ProfileExportError:
            raise RecoveryPackError() from None
        profile_identity = _require_private_file(profile_path)
        guide_path = pack_dir / "RECOVERY.txt"
        guide_identity = _write_guide(guide_path, directory_identity)

        final_directory = _require_private_directory(pack_dir)
        if not _same_inode(final_directory, directory_identity):
            raise RecoveryPackError()
        if {entry.name for entry in pack_dir.iterdir()} != _PACK_FILES:
            raise RecoveryPackError()
        if not _same_inode(_require_private_file(profile_path), profile_identity):
            raise RecoveryPackError()
        if not _same_inode(_require_private_file(guide_path), guide_identity):
            raise RecoveryPackError()
    except RecoveryPackError:
        _remove_owned_file(pack_dir / "RECOVERY.txt", guide_identity)
        _remove_owned_file(pack_dir / "client.vless", profile_identity)
        _remove_owned_directory(pack_dir, directory_identity)
        raise
    except (OSError, TypeError, ValueError, UnicodeError, RecursionError):
        _remove_owned_file(pack_dir / "RECOVERY.txt", guide_identity)
        _remove_owned_file(pack_dir / "client.vless", profile_identity)
        _remove_owned_directory(pack_dir, directory_identity)
        raise RecoveryPackError() from None
