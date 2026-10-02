"""Offline, in-place application-source release updates for a stopped install."""

from __future__ import annotations

import fcntl
import os
import re
import secrets
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

_MAX_FILES = 4096
_MAX_BLOB_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_TREE_BYTES = 4 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 15
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_RESERVED_COMPONENTS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".ruff_cache",
    "state",
    "transitvpn.egg-info",
    "__pycache__",
}
_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_CLOEXEC", 0)
)
_REFUSED = "release operation was refused"
_RESTORED = "release operation failed; the prior release was restored"
_ROLLBACK_INCOMPLETE = "release operation failed; rollback was incomplete"


class ReleaseError(Exception):
    """A release request failed with a fixed, non-sensitive message."""


@dataclass(frozen=True)
class ReleaseObservation:
    old_revision: str
    new_revision: str
    changed_file_count: int
    no_op: bool


@dataclass(frozen=True)
class _GitEntry:
    path: str
    mode: int
    oid: str
    data: bytes


@dataclass(frozen=True)
class _Snapshot:
    entry: _GitEntry
    data: bytes
    stat_result: os.stat_result
    mode_bits: int
    parent_chain: tuple[tuple[tuple[str, ...], int, int, int], ...]


@dataclass(frozen=True)
class _Applied:
    operation: str
    parts: tuple[str, ...]
    old_data: bytes | None
    old_mode: int | None
    new_data: bytes | None
    new_mode: int | None
    new_identity: tuple[int, int] | None


def _refuse() -> None:
    raise ReleaseError(_REFUSED)


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


def _same_directory(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(left.st_mode)
        and stat.S_ISDIR(right.st_mode)
        and (left.st_dev, left.st_ino, left.st_uid) == (right.st_dev, right.st_ino, right.st_uid)
    )


def _run_git(repo: Path, *args: str, output_limit: int = _MAX_TREE_BYTES) -> bytes:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(
        {
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        result = subprocess.run(
            ["git", "--no-replace-objects", "-C", str(repo), *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=_GIT_TIMEOUT_SECONDS,
            env=env,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        _refuse()
    if result.returncode != 0 or len(result.stdout) > output_limit:
        _refuse()
    return result.stdout


def _source_root(source_repo: Path) -> Path:
    try:
        requested = Path(source_repo)
        if not requested.is_absolute():
            _refuse()
        resolved = requested.resolve(strict=True)
        if not resolved.is_dir():
            _refuse()
        raw_root = _run_git(resolved, "rev-parse", "--show-toplevel", output_limit=4096)
        root = Path(raw_root.decode("utf-8", "strict").strip()).resolve(strict=True)
        if not root.is_dir():
            _refuse()
        return root
    except ReleaseError:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        _refuse()


def _validate_revision(value: str) -> str:
    if not isinstance(value, str) or _REVISION_RE.fullmatch(value) is None:
        _refuse()
    return value


def _safe_parts(path_bytes: bytes) -> tuple[str, ...]:
    try:
        path = path_bytes.decode("utf-8", "strict")
    except UnicodeError:
        _refuse()
    if (
        not path
        or path.startswith("/")
        or "\\" in path
        or any(ord(char) < 32 or ord(char) == 127 for char in path)
    ):
        _refuse()
    parts = tuple(path.split("/"))
    if any(part in {"", ".", ".."} or part in _RESERVED_COMPONENTS for part in parts):
        _refuse()
    if any(part.startswith(".") and part.lower() == ".git" for part in parts):
        _refuse()
    return parts


def _dependency_declaration(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    return (
        name in {"pyproject.toml", "setup.py", "setup.cfg", "pipfile", "pipfile.lock"}
        or name.startswith(("requirements", "constraints"))
        or name.endswith(".lock")
    )


def _load_revision(repo: Path, revision: str) -> dict[str, _GitEntry]:
    _run_git(repo, "cat-file", "-e", f"{revision}^{{commit}}", output_limit=0)
    raw_tree = _run_git(
        repo,
        "ls-tree",
        "-r",
        "-z",
        "--full-tree",
        "--full-name",
        revision,
        output_limit=_MAX_TREE_BYTES,
    )
    if raw_tree and not raw_tree.endswith(b"\0"):
        _refuse()
    records = raw_tree.split(b"\0")
    if records and records[-1] == b"":
        records.pop()
    if len(records) > _MAX_FILES:
        _refuse()
    entries: dict[str, _GitEntry] = {}
    total_bytes = 0
    for record in records:
        metadata, separator, path_bytes = record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            _refuse()
        mode_text, object_type, oid_text = fields
        if mode_text not in {b"100644", b"100755"} or object_type != b"blob":
            _refuse()
        try:
            mode = int(mode_text, 8)
            oid = oid_text.decode("ascii", "strict")
        except (ValueError, UnicodeError):
            _refuse()
        if _OBJECT_RE.fullmatch(oid) is None:
            _refuse()
        parts = _safe_parts(path_bytes)
        path = "/".join(parts)
        if path in entries:
            _refuse()
        size_bytes = _run_git(repo, "cat-file", "-s", oid, output_limit=64)
        try:
            size = int(size_bytes.decode("ascii", "strict"))
        except (ValueError, UnicodeError):
            _refuse()
        if size < 0 or size > _MAX_BLOB_BYTES:
            _refuse()
        total_bytes += size
        if total_bytes > _MAX_TOTAL_BYTES:
            _refuse()
        data = _run_git(repo, "cat-file", "blob", oid, output_limit=_MAX_BLOB_BYTES)
        if len(data) != size:
            _refuse()
        entries[path] = _GitEntry(path, mode, oid, data)
    return entries


def _validate_dependency_compatibility(
    old_entries: dict[str, _GitEntry], new_entries: dict[str, _GitEntry]
) -> None:
    names = {path for path in set(old_entries) | set(new_entries) if _dependency_declaration(path)}
    for path in names:
        old = old_entries.get(path)
        new = new_entries.get(path)
        if old is None or new is None or old.mode != new.mode or old.data != new.data:
            _refuse()


def _check_path_shapes(
    old_entries: dict[str, _GitEntry], new_entries: dict[str, _GitEntry]
) -> None:
    old_paths = set(old_entries)
    new_paths = set(new_entries)
    for path in old_paths | new_paths:
        pieces = path.split("/")
        for index in range(1, len(pieces)):
            parent = "/".join(pieces[:index])
            if (parent in old_paths and parent not in new_paths) or (
                parent in new_paths and parent not in old_paths
            ):
                _refuse()


def _path_value(path: Path) -> str:
    try:
        value = os.fspath(path)
        if not isinstance(value, str) or not os.path.isabs(value):
            _refuse()
        if ".." in value.split(os.sep):
            _refuse()
        return os.path.normpath(value)
    except (OSError, TypeError, ValueError):
        _refuse()


def _open_destination(path_value: str) -> tuple[int, os.stat_result]:
    fd: int | None = None
    # Walk each path component separately so no symlink can be traversed.
    try:
        fd = os.open(os.path.sep, _DIRECTORY_FLAGS)
        current = os.path.sep
        for component in Path(path_value).parts[1:]:
            try:
                git_entry = os.stat(".git", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                git_entry = None
            if git_entry is not None:
                _refuse()
            before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                _refuse()
            child = os.open(component, _DIRECTORY_FLAGS, dir_fd=fd)
            opened = os.fstat(child)
            if not _same_directory(before, opened):
                os.close(child)
                _refuse()
            os.close(fd)
            fd = child
            current = os.path.join(current, component)
        info = os.fstat(fd)
        if info.st_uid != os.geteuid():
            _refuse()
        try:
            if os.stat(".git", dir_fd=fd, follow_symlinks=False) is not None:
                _refuse()
        except FileNotFoundError:
            pass
        result = fd
        fd = None
        return result, info
    except ReleaseError:
        raise
    except OSError:
        _refuse()
    finally:
        if fd is not None:
            os.close(fd)


def _verify_root_binding(path_value: str, root_fd: int, expected: os.stat_result) -> None:
    current_fd, current = _open_destination(path_value)
    try:
        if not _same_directory(expected, os.fstat(root_fd)) or not _same_directory(
            expected, current
        ):
            _refuse()
    finally:
        os.close(current_fd)


def _parent_context(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    create: bool = False,
    created_dirs: list[tuple[tuple[str, ...], tuple[int, int]]] | None = None,
) -> tuple[int, str, tuple[tuple[tuple[str, ...], int, int, int], ...]] | None:
    parent_fd = os.dup(root_fd)
    chain: list[tuple[tuple[str, ...], int, int, int]] = []
    prefix: list[str] = []
    try:
        for component in parts[:-1]:
            try:
                before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    return None
                try:
                    os.mkdir(component, 0o755, dir_fd=parent_fd)
                    before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                    if not stat.S_ISDIR(before.st_mode):
                        _refuse()
                    if created_dirs is not None:
                        created_dirs.append(
                            (tuple(prefix + [component]), (before.st_dev, before.st_ino))
                        )
                    os.fsync(parent_fd)
                except FileExistsError:
                    before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                _refuse()
            child_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            opened = os.fstat(child_fd)
            if not _same_directory(before, opened):
                os.close(child_fd)
                _refuse()
            prefix.append(component)
            chain.append((tuple(prefix), opened.st_dev, opened.st_ino, opened.st_uid))
            os.close(parent_fd)
            parent_fd = child_fd
        result = parent_fd
        parent_fd = -1
        return result, parts[-1], tuple(chain)
    except ReleaseError:
        raise
    except OSError:
        _refuse()
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _chain_matches(
    current: tuple[tuple[tuple[str, ...], int, int, int], ...],
    expected: tuple[tuple[tuple[str, ...], int, int, int], ...],
) -> bool:
    return current == expected


def _read_file_at(parent_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    fd: int | None = None
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid():
            _refuse()
        if before.st_size < 0 or before.st_size > _MAX_BLOB_BYTES:
            _refuse()
        fd = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
        opened = os.fstat(fd)
        if not _same_file(before, opened):
            _refuse()
        with os.fdopen(fd, "rb", closefd=True) as handle:
            fd = None
            data = handle.read(_MAX_BLOB_BYTES + 1)
            after_fd = os.fstat(handle.fileno())
        after_name = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(data) > _MAX_BLOB_BYTES
            or not _same_file(opened, after_fd)
            or not _same_file(opened, after_name)
        ):
            _refuse()
        return data, after_name
    except ReleaseError:
        raise
    except (OSError, ValueError):
        _refuse()
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _snapshot(root_fd: int, entry: _GitEntry) -> _Snapshot:
    parts = tuple(entry.path.split("/"))
    context = _parent_context(root_fd, parts)
    if context is None:
        _refuse()
    parent_fd, name, chain = context
    try:
        data, info = _read_file_at(parent_fd, name)
        expected_executable = entry.mode == 0o100755
        actual_executable = bool(stat.S_IMODE(info.st_mode) & 0o111)
        if data != entry.data or expected_executable != actual_executable:
            _refuse()
        return _Snapshot(entry, data, info, stat.S_IMODE(info.st_mode), chain)
    finally:
        os.close(parent_fd)


def _entry_if_present(
    root_fd: int, path: str
) -> tuple[os.stat_result | None, tuple[tuple[tuple[str, ...], int, int, int], ...]]:
    parts = tuple(path.split("/"))
    context = _parent_context(root_fd, parts)
    if context is None:
        return None, ()
    parent_fd, name, chain = context
    try:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        return info, chain
    except OSError:
        _refuse()
    finally:
        os.close(parent_fd)


def _verify_snapshot(root_fd: int, snapshot: _Snapshot) -> tuple[int, str]:
    parts = tuple(snapshot.entry.path.split("/"))
    context = _parent_context(root_fd, parts)
    if context is None:
        _refuse()
    parent_fd, name, chain = context
    if not _chain_matches(chain, snapshot.parent_chain):
        os.close(parent_fd)
        _refuse()
    try:
        data, current = _read_file_at(parent_fd, name)
        if not _same_file(snapshot.stat_result, current) or data != snapshot.data:
            _refuse()
        return parent_fd, name
    except Exception:
        os.close(parent_fd)
        raise


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _stage_file(parent_fd: int, data: bytes, mode_bits: int) -> tuple[str, tuple[int, int]]:
    name = f".transitvpn-release-{secrets.token_hex(16)}.tmp"
    fd: int | None = None
    identity: tuple[int, int] | None = None
    try:
        fd = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=parent_fd)
        opened = os.fstat(fd)
        identity = (opened.st_dev, opened.st_ino)
        _write_all(fd, data)
        os.fchmod(fd, mode_bits)
        os.fsync(fd)
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino) != identity or not stat.S_ISREG(final.st_mode):
            _refuse()
        os.close(fd)
        fd = None
        return name, identity
    except Exception:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        cleanup_ok = True
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if identity is not None and (current.st_dev, current.st_ino) == identity:
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            cleanup_ok = False
        if not cleanup_ok:
            raise ReleaseError(_ROLLBACK_INCOMPLETE) from None
        raise


def _remove_temp_if_owned(parent_fd: int, name: str, identity: tuple[int, int]) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    if (current.st_dev, current.st_ino) != identity or not stat.S_ISREG(current.st_mode):
        return False
    try:
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return True
    except OSError:
        return False


def _desired_mode(existing_mode: int | None, git_mode: int) -> int:
    executable = git_mode == 0o100755
    if existing_mode is None:
        return 0o755 if executable else 0o644
    current = existing_mode & 0o777
    current_executable = bool(current & 0o111)
    if current_executable == executable:
        return current
    return current | 0o111 if executable else current & ~0o111


def _current_matches(
    parent_fd: int,
    name: str,
    *,
    data: bytes,
    identity: tuple[int, int] | None = None,
    mode_bits: int | None = None,
) -> bool:
    try:
        current_data, info = _read_file_at(parent_fd, name)
    except ReleaseError:
        return False
    return (
        current_data == data
        and (identity is None or (info.st_dev, info.st_ino) == identity)
        and (mode_bits is None or stat.S_IMODE(info.st_mode) == mode_bits)
    )


def _replace_from_memory(
    root_fd: int,
    path: str,
    data: bytes,
    mode_bits: int,
    *,
    expected_data: bytes,
    expected_stat: os.stat_result,
    expected_chain: tuple[tuple[tuple[str, ...], int, int, int], ...],
    on_installed: Callable[[tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    snapshot = _Snapshot(
        _GitEntry(
            path,
            0o100755 if stat.S_IMODE(expected_stat.st_mode) & 0o111 else 0o100644,
            "0" * 40,
            expected_data,
        ),
        expected_data,
        expected_stat,
        stat.S_IMODE(expected_stat.st_mode),
        expected_chain,
    )
    parent_fd, name = _verify_snapshot(root_fd, snapshot)
    staged_name: str | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        staged_name, staged_identity = _stage_file(parent_fd, data, mode_bits)
        # Recheck immediately before the atomic replacement while holding the destination lock.
        data_now, stat_now = _read_file_at(parent_fd, name)
        if not _same_file(expected_stat, stat_now) or data_now != expected_data:
            _refuse()
        os.replace(staged_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        staged_name = None
        if staged_identity is None:
            _refuse()
        identity = staged_identity
        if on_installed is not None:
            on_installed(identity)
        installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            (installed.st_dev, installed.st_ino) != identity
            or not stat.S_ISREG(installed.st_mode)
            or stat.S_IMODE(installed.st_mode) != mode_bits
        ):
            _refuse()
        os.fsync(parent_fd)
        return identity
    finally:
        cleanup_failed = False
        if staged_name is not None and staged_identity is not None:
            cleanup_failed = not _remove_temp_if_owned(parent_fd, staged_name, staged_identity)
        os.close(parent_fd)
        if cleanup_failed:
            raise ReleaseError(_ROLLBACK_INCOMPLETE) from None


def _add_from_memory(
    root_fd: int,
    path: str,
    data: bytes,
    mode_bits: int,
    created_dirs: list[tuple[tuple[str, ...], tuple[int, int]]],
    on_installed: Callable[[tuple[int, int]], None] | None = None,
) -> tuple[int, int]:
    parts = tuple(path.split("/"))
    context = _parent_context(root_fd, parts, create=True, created_dirs=created_dirs)
    if context is None:
        _refuse()
    parent_fd, name, _chain = context
    staged_name: str | None = None
    staged_identity: tuple[int, int] | None = None
    try:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _refuse()
        staged_name, staged_identity = _stage_file(parent_fd, data, mode_bits)
        # link() is atomic and fails if an untracked entry appeared meanwhile.
        os.link(
            staged_name, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False
        )
        if staged_identity is None:
            _refuse()
        identity = staged_identity
        if on_installed is not None:
            on_installed(identity)
        installed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (installed.st_dev, installed.st_ino) != identity:
            _refuse()
        os.unlink(staged_name, dir_fd=parent_fd)
        staged_name = None
        os.fsync(parent_fd)
        if not stat.S_ISREG(installed.st_mode) or stat.S_IMODE(installed.st_mode) != mode_bits:
            _refuse()
        return identity
    finally:
        cleanup_failed = False
        if staged_name is not None and staged_identity is not None:
            cleanup_failed = not _remove_temp_if_owned(parent_fd, staged_name, staged_identity)
        os.close(parent_fd)
        if cleanup_failed:
            raise ReleaseError(_ROLLBACK_INCOMPLETE) from None


def _remove_expected(
    root_fd: int,
    snapshot: _Snapshot,
    on_removed: Callable[[], None] | None = None,
) -> None:
    parent_fd, name = _verify_snapshot(root_fd, snapshot)
    try:
        data_now, info = _read_file_at(parent_fd, name)
        if not _same_file(snapshot.stat_result, info) or data_now != snapshot.data:
            _refuse()
        os.unlink(name, dir_fd=parent_fd)
        if on_removed is not None:
            on_removed()
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _restore_removed(root_fd: int, path: str, data: bytes, mode_bits: int) -> bool:
    parts = tuple(path.split("/"))
    context = _parent_context(root_fd, parts)
    if context is None:
        return False
    parent_fd, name, _chain = context
    try:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return False
        staged, identity = _stage_file(parent_fd, data, mode_bits)
        cleanup_ok = True
        try:
            os.link(staged, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            os.unlink(staged, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            cleanup_ok = _remove_temp_if_owned(parent_fd, staged, identity)
        return cleanup_ok and _current_matches(
            parent_fd, name, data=data, identity=identity, mode_bits=mode_bits
        )
    except (OSError, ReleaseError):
        return False
    finally:
        os.close(parent_fd)


def _rollback(
    root_fd: int,
    applied: list[_Applied],
    created_dirs: list[tuple[tuple[str, ...], tuple[int, int]]],
) -> bool:
    complete = True
    for change in reversed(applied):
        path = "/".join(change.parts)
        try:
            context = _parent_context(root_fd, change.parts)
        except (OSError, ReleaseError, TypeError, IndexError):
            complete = False
            continue
        if context is None:
            complete = False
            continue
        parent_fd, name, _chain = context
        try:
            if change.operation == "replace":
                if (
                    change.old_data is None
                    or change.old_mode is None
                    or change.new_data is None
                    or change.new_mode is None
                ):
                    complete = False
                    continue
                if not _current_matches(
                    parent_fd,
                    name,
                    data=change.new_data,
                    identity=change.new_identity,
                    mode_bits=change.new_mode,
                ):
                    complete = False
                    continue
                current_data, current_stat = _read_file_at(parent_fd, name)
                if current_data != change.new_data:
                    complete = False
                    continue
                _replace_from_memory(
                    root_fd,
                    path,
                    change.old_data,
                    change.old_mode,
                    expected_data=change.new_data,
                    expected_stat=current_stat,
                    expected_chain=_chain,
                )
            elif change.operation == "add":
                if change.new_data is None or not _current_matches(
                    parent_fd,
                    name,
                    data=change.new_data,
                    identity=change.new_identity,
                    mode_bits=change.new_mode,
                ):
                    complete = False
                    continue
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            elif change.operation == "delete":
                if change.old_data is None or change.old_mode is None:
                    complete = False
                    continue
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    if not _restore_removed(root_fd, path, change.old_data, change.old_mode):
                        complete = False
                else:
                    complete = False
            else:
                complete = False
        except (OSError, ReleaseError, TypeError, IndexError):
            complete = False
        finally:
            os.close(parent_fd)
    for parts, identity in reversed(created_dirs):
        try:
            context = _parent_context(root_fd, parts)
        except (OSError, ReleaseError, TypeError, IndexError):
            complete = False
            continue
        if context is None:
            complete = False
            continue
        parent_fd, name, _chain = context
        try:
            try:
                info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                complete = False
                continue
            child_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            try:
                if os.listdir(child_fd):
                    complete = False
                    continue
                os.rmdir(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(child_fd)
        except OSError:
            complete = False
        finally:
            os.close(parent_fd)
    return complete


def _assert_no_dependency_changes(old: dict[str, _GitEntry], new: dict[str, _GitEntry]) -> None:
    _validate_dependency_compatibility(old, new)
    _check_path_shapes(old, new)


def apply_release(
    source_repo: Path,
    destination: Path,
    expected_revision: str,
    new_revision: str,
) -> ReleaseObservation:
    """Apply one dependency-compatible Git release to an existing stopped install."""
    expected = _validate_revision(expected_revision)
    requested = _validate_revision(new_revision)
    source_root = _source_root(Path(source_repo))
    destination_value = _path_value(Path(destination))
    package_root = Path(__file__).resolve().parent.parent
    if destination_value == str(source_root) or destination_value == str(package_root):
        _refuse()
    try:
        common = os.path.commonpath((destination_value, str(source_root)))
        if common in {destination_value, str(source_root)}:
            _refuse()
    except ValueError:
        _refuse()

    old_entries = _load_revision(source_root, expected)
    new_entries = old_entries if requested == expected else _load_revision(source_root, requested)
    _assert_no_dependency_changes(old_entries, new_entries)

    root_fd, root_info = _open_destination(destination_value)
    applied: list[_Applied] = []
    created_dirs: list[tuple[tuple[str, ...], tuple[int, int]]] = []
    try:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            _refuse()
        if root_info.st_uid != os.geteuid():
            _refuse()
        snapshots = {path: _snapshot(root_fd, entry) for path, entry in old_entries.items()}
        changed = {
            path
            for path in old_entries.keys() & new_entries.keys()
            if old_entries[path].data != new_entries[path].data
            or old_entries[path].mode != new_entries[path].mode
        }
        additions = set(new_entries) - set(old_entries)
        removals = set(old_entries) - set(new_entries)
        for path in additions:
            info, _chain = _entry_if_present(root_fd, path)
            if info is not None:
                _refuse()
        if requested == expected:
            return ReleaseObservation(expected, requested, 0, True)

        try:
            for path in sorted(changed):
                _verify_root_binding(destination_value, root_fd, root_info)
                snapshot = snapshots[path]
                entry = new_entries[path]
                mode_bits = _desired_mode(snapshot.mode_bits, entry.mode)
                _replace_from_memory(
                    root_fd,
                    path,
                    entry.data,
                    mode_bits,
                    expected_data=snapshot.data,
                    expected_stat=snapshot.stat_result,
                    expected_chain=snapshot.parent_chain,
                    on_installed=lambda identity, p=path, snap=snapshot, e=entry, m=mode_bits: (
                        applied.append(
                            _Applied(
                                "replace",
                                tuple(p.split("/")),
                                snap.data,
                                snap.mode_bits,
                                e.data,
                                m,
                                identity,
                            )
                        )
                    ),
                )
            for path in sorted(additions):
                _verify_root_binding(destination_value, root_fd, root_info)
                entry = new_entries[path]
                mode_bits = _desired_mode(None, entry.mode)
                _add_from_memory(
                    root_fd,
                    path,
                    entry.data,
                    mode_bits,
                    created_dirs,
                    on_installed=lambda identity, p=path, e=entry, m=mode_bits: applied.append(
                        _Applied("add", tuple(p.split("/")), None, None, e.data, m, identity)
                    ),
                )
            for path in sorted(removals):
                _verify_root_binding(destination_value, root_fd, root_info)
                snapshot = snapshots[path]
                _remove_expected(
                    root_fd,
                    snapshot,
                    on_removed=lambda p=path, snap=snapshot: applied.append(
                        _Applied(
                            "delete",
                            tuple(p.split("/")),
                            snap.data,
                            snap.mode_bits,
                            None,
                            None,
                            None,
                        )
                    ),
                )
        except Exception as exc:  # noqa: BLE001 -- mutation failures must enter rollback
            recovered = _rollback(root_fd, applied, created_dirs)
            incomplete_error = isinstance(exc, ReleaseError) and str(exc) == _ROLLBACK_INCOMPLETE
            raise ReleaseError(
                _RESTORED if recovered and not incomplete_error else _ROLLBACK_INCOMPLETE
            ) from None
        return ReleaseObservation(
            expected, requested, len(changed) + len(additions) + len(removals), False
        )
    finally:
        try:
            fcntl.flock(root_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(root_fd)
