"""Private backup and restore of the two managed Xray configuration files."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Any

_CONFIG_NAMES = ("xray-server.json", "xray-client.json")
_PID_NAMES = ("tunnel.pid", "tunnel-client.pid")
_MAX_CONFIG_BYTES = 4 * 1024 * 1024
_DIRECTORY_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
)


class ConfigBackupError(Exception):
    """A private backup or restore could not be completed safely."""


def _refuse() -> None:
    raise ConfigBackupError("configuration backup or restore was refused")


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        stat.S_IFMT(left.st_mode),
        stat.S_IMODE(left.st_mode),
        left.st_uid,
        left.st_nlink,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        stat.S_IFMT(right.st_mode),
        stat.S_IMODE(right.st_mode),
        right.st_uid,
        right.st_nlink,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _open_private_directory(path: Path) -> tuple[int, os.stat_result]:
    try:
        before = path.lstat()
        if (
            not stat.S_ISDIR(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o700
            or before.st_uid != os.geteuid()
        ):
            _refuse()
        directory_fd = os.open(path, _DIRECTORY_FLAGS)
        opened = os.fstat(directory_fd)
        if not _same_file(before, opened):
            os.close(directory_fd)
            _refuse()
        return directory_fd, opened
    except ConfigBackupError:
        raise
    except OSError:
        _refuse()


def _entry_stat(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _refuse()


def _require_absent(directory_fd: int, names: tuple[str, ...]) -> None:
    for name in names:
        if _entry_stat(directory_fd, name) is not None:
            _refuse()


def _read_private_file(directory_fd: int, name: str) -> bytes:
    fd: int | None = None
    try:
        before = _entry_stat(directory_fd, name)
        if (
            before is None
            or not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_size > _MAX_CONFIG_BYTES
        ):
            _refuse()
        fd = os.open(name, _READ_FLAGS, dir_fd=directory_fd)
        opened = os.fstat(fd)
        if not _same_file(before, opened):
            _refuse()
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            data = handle.read(_MAX_CONFIG_BYTES + 1)
            after = os.fstat(handle.fileno())
        current = _entry_stat(directory_fd, name)
        if (
            len(data) > _MAX_CONFIG_BYTES
            or current is None
            or not _same_file(opened, after)
            or not _same_file(opened, current)
        ):
            _refuse()
        return data
    except ConfigBackupError:
        raise
    except (OSError, ValueError):
        _refuse()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _snapshot_private_file(directory_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    before = _entry_stat(directory_fd, name)
    if (
        before is None
        or not stat.S_ISREG(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or before.st_size > _MAX_CONFIG_BYTES
    ):
        _refuse()
    data = _read_private_file(directory_fd, name)
    after = _entry_stat(directory_fd, name)
    if after is None or not _same_file(before, after):
        _refuse()
    return data, before


def _require_directory_binding(
    directory_fd: int, path: Path, expected: os.stat_result
) -> None:
    try:
        opened = os.fstat(directory_fd)
        named = path.lstat()
    except OSError:
        _refuse()
    for actual in (opened, named):
        if (
            not stat.S_ISDIR(actual.st_mode)
            or stat.S_IMODE(actual.st_mode) != 0o700
            or actual.st_uid != os.geteuid()
            or (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino)
        ):
            _refuse()


def _verify_backup_snapshot(
    backup_fd: int,
    source: Path,
    backup_info: os.stat_result,
    configs: dict[str, bytes],
    config_stats: dict[str, os.stat_result],
) -> None:
    try:
        if set(os.listdir(backup_fd)) != set(_CONFIG_NAMES):
            _refuse()
        named = source.lstat()
        opened = os.fstat(backup_fd)
    except OSError:
        _refuse()
    if not _same_file(backup_info, named) or not _same_file(backup_info, opened):
        _refuse()
    for name in _CONFIG_NAMES:
        current = _entry_stat(backup_fd, name)
        if current is None or not _same_file(config_stats[name], current):
            _refuse()
        if _read_private_file(backup_fd, name) != configs[name]:
            _refuse()


def _verify_replace_snapshot(
    state_fd: int,
    state_dir: Path,
    state_info: os.stat_result,
    original_configs: dict[str, bytes],
    original_stats: dict[str, os.stat_result],
    restored_configs: dict[str, bytes],
    staged_identities: dict[str, tuple[int, int]],
    replaced: set[str],
) -> None:
    _require_directory_binding(state_fd, state_dir, state_info)
    _require_absent(state_fd, _PID_NAMES)
    for name in _CONFIG_NAMES:
        current = _entry_stat(state_fd, name)
        if current is None:
            _refuse()
        if name in replaced:
            if (current.st_dev, current.st_ino) != staged_identities[name]:
                _refuse()
            if _read_private_file(state_fd, name) != restored_configs[name]:
                _refuse()
        else:
            if not _same_file(original_stats[name], current):
                _refuse()
            if _read_private_file(state_fd, name) != original_configs[name]:
                _refuse()


def _replace_private_configs(
    state_fd: int,
    state_dir: Path,
    state_info: os.stat_result,
    backup_fd: int,
    source: Path,
    backup_info: os.stat_result,
    backup_configs: dict[str, bytes],
    backup_stats: dict[str, os.stat_result],
    original_configs: dict[str, bytes],
    original_stats: dict[str, os.stat_result],
    restored_configs: dict[str, bytes],
) -> None:
    token = secrets.token_hex(16)
    staged_names = {
        name: f".transitvpn-restore-{token}-{name}.tmp" for name in _CONFIG_NAMES
    }
    staged_identities: dict[str, tuple[int, int]] = {}
    replaced: set[str] = set()
    try:
        for name in _CONFIG_NAMES:
            staged_identities[name] = _write_private_file(
                state_fd, staged_names[name], restored_configs[name]
            )
        os.fsync(state_fd)
        _verify_replace_snapshot(
            state_fd,
            state_dir,
            state_info,
            original_configs,
            original_stats,
            restored_configs,
            staged_identities,
            replaced,
        )
        for name in _CONFIG_NAMES:
            _verify_backup_snapshot(
                backup_fd, source, backup_info, backup_configs, backup_stats
            )
            _verify_replace_snapshot(
                state_fd,
                state_dir,
                state_info,
                original_configs,
                original_stats,
                restored_configs,
                staged_identities,
                replaced,
            )
            staged = _entry_stat(state_fd, staged_names[name])
            if (
                staged is None
                or (staged.st_dev, staged.st_ino) != staged_identities[name]
                or _read_private_file(state_fd, staged_names[name]) != restored_configs[name]
            ):
                _refuse()
            os.replace(
                staged_names[name],
                name,
                src_dir_fd=state_fd,
                dst_dir_fd=state_fd,
            )
            current = _entry_stat(state_fd, name)
            if (
                current is None
                or (current.st_dev, current.st_ino) != staged_identities[name]
                or _read_private_file(state_fd, name) != restored_configs[name]
            ):
                _refuse()
            replaced.add(name)
        _verify_replace_snapshot(
            state_fd,
            state_dir,
            state_info,
            original_configs,
            original_stats,
            restored_configs,
            staged_identities,
            replaced,
        )
        os.fsync(state_fd)
    except (ConfigBackupError, OSError, ValueError):
        # A failed rename can have taken effect before an error was reported.
        # Roll back only files whose current inode is still one of our staged files.
        for name in _CONFIG_NAMES:
            current = _entry_stat(state_fd, name)
            if (
                current is not None
                and (current.st_dev, current.st_ino) == staged_identities.get(name)
                and _read_private_file(state_fd, name) == restored_configs[name]
            ):
                replaced.add(name)
        rollback_ok = True
        for name in reversed(_CONFIG_NAMES):
            if name not in replaced:
                continue
            rollback_name = f".transitvpn-rollback-{token}-{name}.tmp"
            rollback_identity: tuple[int, int] | None = None
            try:
                current = _entry_stat(state_fd, name)
                if (
                    current is None
                    or (current.st_dev, current.st_ino) != staged_identities[name]
                    or _read_private_file(state_fd, name) != restored_configs[name]
                ):
                    _refuse()
                rollback_identity = _write_private_file(
                    state_fd, rollback_name, original_configs[name]
                )
                _require_absent(state_fd, _PID_NAMES)
                current = _entry_stat(state_fd, name)
                if (
                    current is None
                    or (current.st_dev, current.st_ino) != staged_identities[name]
                    or _read_private_file(state_fd, name) != restored_configs[name]
                ):
                    _refuse()
                os.replace(
                    rollback_name,
                    name,
                    src_dir_fd=state_fd,
                    dst_dir_fd=state_fd,
                )
                restored = _entry_stat(state_fd, name)
                if (
                    restored is None
                    or (restored.st_dev, restored.st_ino) != rollback_identity
                    or _read_private_file(state_fd, name) != original_configs[name]
                ):
                    _refuse()
            except (ConfigBackupError, OSError, ValueError):
                rollback_ok = False
            finally:
                _remove_if_owned(state_fd, rollback_name, rollback_identity)
        if rollback_ok:
            try:
                os.fsync(state_fd)
            except OSError:
                rollback_ok = False
        if not rollback_ok:
            _refuse()
        _refuse()
    finally:
        for name, identity in staged_identities.items():
            _remove_if_owned(state_fd, staged_names[name], identity)


def _parse_config(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeError, ValueError):
        _refuse()
    if not isinstance(value, dict):
        _refuse()
    return value


def _outside_checkout(path: Path) -> bool:
    try:
        checkout = Path(__file__).resolve().parents[1]
        candidate = Path(os.path.abspath(path))
        return candidate != checkout and checkout not in candidate.parents
    except OSError:
        return False


def _open_backup_parent(destination: Path) -> tuple[int, str]:
    if (
        not destination.is_absolute()
        or destination.name in {"", ".", ".."}
        or not _outside_checkout(destination)
    ):
        _refuse()
    try:
        parent = destination.parent
        if parent.resolve(strict=True) != Path(os.path.abspath(parent)):
            _refuse()
    except (OSError, RuntimeError):
        _refuse()
    parent_fd, _ = _open_private_directory(destination.parent)
    if _entry_stat(parent_fd, destination.name) is not None:
        os.close(parent_fd)
        _refuse()
    return parent_fd, destination.name


def _write_private_file(directory_fd: int, name: str, data: bytes) -> tuple[int, int]:
    fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        fd = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=directory_fd)
        created = os.fstat(fd)
        identity = (created.st_dev, created.st_ino)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            _refuse()
        os.fchmod(fd, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _refuse()
            view = view[written:]
        os.fsync(fd)
        final = os.fstat(fd)
        if (
            (final.st_dev, final.st_ino) != identity
            or not stat.S_ISREG(final.st_mode)
            or stat.S_IMODE(final.st_mode) != 0o600
            or final.st_uid != os.geteuid()
            or final.st_nlink != 1
            or final.st_size != len(data)
        ):
            _refuse()
        os.close(fd)
        fd = None
        written_data = _read_private_file(directory_fd, name)
        if not hmac.compare_digest(
            hashlib.sha256(written_data).digest(), hashlib.sha256(data).digest()
        ):
            _refuse()
        return identity
    except ConfigBackupError:
        _remove_if_owned(directory_fd, name, identity)
        raise
    except (OSError, ValueError):
        _remove_if_owned(directory_fd, name, identity)
        _refuse()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _remove_if_owned(
    directory_fd: int, name: str, identity: tuple[int, int] | None
) -> None:
    if identity is None:
        return
    try:
        current = _entry_stat(directory_fd, name)
        if current is not None and (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=directory_fd)
    except OSError:
        pass


def _remove_owned_directory(
    parent_fd: int, name: str, identity: tuple[int, int] | None
) -> None:
    if identity is None:
        return
    try:
        current = _entry_stat(parent_fd, name)
        if (
            current is not None
            and stat.S_ISDIR(current.st_mode)
            and (current.st_dev, current.st_ino) == identity
        ):
            os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        pass


def backup_configs(state_dir: Path, destination: Path) -> None:
    """Copy only the stopped deployment's two configs to a new private directory."""
    state_fd: int | None = None
    parent_fd: int | None = None
    backup_fd: int | None = None
    backup_identity: tuple[int, int] | None = None
    created_files: dict[str, tuple[int, int]] = {}
    complete = False
    try:
        state_fd, _ = _open_private_directory(state_dir)
        _require_absent(state_fd, _PID_NAMES)
        configs = {
            name: _read_private_file(state_fd, name) for name in _CONFIG_NAMES
        }
        for data in configs.values():
            _parse_config(data)

        parent_fd, name = _open_backup_parent(destination)
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        created_directory = _entry_stat(parent_fd, name)
        if (
            created_directory is None
            or not stat.S_ISDIR(created_directory.st_mode)
            or created_directory.st_uid != os.geteuid()
        ):
            _refuse()
        backup_identity = (created_directory.st_dev, created_directory.st_ino)
        backup_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        backup_info = os.fstat(backup_fd)
        if (backup_info.st_dev, backup_info.st_ino) != backup_identity:
            _refuse()
        os.fchmod(backup_fd, 0o700)
        if (
            not stat.S_ISDIR(backup_info.st_mode)
            or stat.S_IMODE(os.fstat(backup_fd).st_mode) != 0o700
            or os.fstat(backup_fd).st_uid != os.geteuid()
        ):
            _refuse()

        for filename, data in configs.items():
            created_files[filename] = _write_private_file(backup_fd, filename, data)
        os.fsync(backup_fd)
        complete = True
    except ConfigBackupError:
        raise
    except (OSError, ValueError):
        _refuse()
    finally:
        if not complete and backup_fd is not None:
            for filename, identity in created_files.items():
                _remove_if_owned(backup_fd, filename, identity)
        if backup_fd is not None:
            try:
                os.close(backup_fd)
            except OSError:
                pass
        if not complete and parent_fd is not None:
            _remove_owned_directory(parent_fd, name, backup_identity)
        if parent_fd is not None:
            try:
                os.close(parent_fd)
            except OSError:
                pass
        if state_fd is not None:
            try:
                os.close(state_fd)
            except OSError:
                pass


def restore_configs(
    state_dir: Path,
    source: Path,
    *,
    xray_binary: str = "xray",
    replace_existing: bool = False,
) -> None:
    """Validate and restore two configs from a trusted private backup."""
    backup_fd: int | None = None
    state_fd: int | None = None
    backup_info: os.stat_result | None = None
    state_info: os.stat_result | None = None
    backup_stats: dict[str, os.stat_result] = {}
    original_configs: dict[str, bytes] = {}
    original_stats: dict[str, os.stat_result] = {}
    created_files: dict[str, tuple[int, int]] = {}
    complete = False
    try:
        if not source.is_absolute() or not _outside_checkout(source):
            _refuse()
        try:
            if source.resolve(strict=True) != Path(os.path.abspath(source)):
                _refuse()
        except (OSError, RuntimeError):
            _refuse()
        backup_fd, backup_info = _open_private_directory(source)
        if set(os.listdir(backup_fd)) != set(_CONFIG_NAMES):
            _refuse()
        configs_bytes: dict[str, bytes] = {}
        for name in _CONFIG_NAMES:
            configs_bytes[name], backup_stats[name] = _snapshot_private_file(
                backup_fd, name
            )
        configs = {name: _parse_config(data) for name, data in configs_bytes.items()}

        state_fd, state_info = _open_private_directory(state_dir)
        _require_absent(state_fd, _PID_NAMES)
        if replace_existing:
            for name in _CONFIG_NAMES:
                original_configs[name], original_stats[name] = _snapshot_private_file(
                    state_fd, name
                )
        else:
            _require_absent(state_fd, _CONFIG_NAMES)

        try:
            from transitvpn.xray import validate_configs

            validate_configs(
                {
                    "server": configs["xray-server.json"],
                    "client": configs["xray-client.json"],
                },
                binary=xray_binary,
            )
        except (OSError, RuntimeError, TypeError, ValueError):
            _refuse()

        assert backup_info is not None and state_info is not None
        _verify_backup_snapshot(
            backup_fd, source, backup_info, configs_bytes, backup_stats
        )
        _require_directory_binding(state_fd, state_dir, state_info)
        if replace_existing:
            _verify_replace_snapshot(
                state_fd,
                state_dir,
                state_info,
                original_configs,
                original_stats,
                configs_bytes,
                {},
                set(),
            )
            _replace_private_configs(
                state_fd,
                state_dir,
                state_info,
                backup_fd,
                source,
                backup_info,
                configs_bytes,
                backup_stats,
                original_configs,
                original_stats,
                configs_bytes,
            )
        else:
            _require_absent(state_fd, _PID_NAMES + _CONFIG_NAMES)
            for filename, data in configs_bytes.items():
                created_files[filename] = _write_private_file(
                    state_fd, filename, data
                )
            _verify_backup_snapshot(
                backup_fd, source, backup_info, configs_bytes, backup_stats
            )
            _require_directory_binding(state_fd, state_dir, state_info)
            _require_absent(state_fd, _PID_NAMES)
            os.fsync(state_fd)
        complete = True
    except ConfigBackupError:
        raise
    except (OSError, ValueError):
        _refuse()
    finally:
        if not complete and state_fd is not None:
            for filename, identity in created_files.items():
                _remove_if_owned(state_fd, filename, identity)
        if state_fd is not None:
            try:
                os.close(state_fd)
            except OSError:
                pass
        if backup_fd is not None:
            try:
                os.close(backup_fd)
            except OSError:
                pass
