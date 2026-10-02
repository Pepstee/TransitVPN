"""Private, idempotent systemd --user installation for one TransitVPN deployment."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

from transitvpn.xray import validate_configs, verify_binary

_SCHEMA = "transitvpn.user-service.v1"
_NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$")
_SERVICE_DIR = Path("state") / "services"


class UserServiceError(RuntimeError):
    """A service operation was refused or could not be completed safely."""


def _name(value: str) -> tuple[str, str]:
    if not isinstance(value, str) or not _NAME_RE.fullmatch(value):
        raise UserServiceError("invalid service name")
    return value, f"transitvpn-{value}.service"


def _safe_unit_value(value: str) -> str:
    if not value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise UserServiceError("unsafe service path")
    if "$" in value or "%" in value:
        raise UserServiceError("unsafe service path")
    return value


def _safe_absolute(value: str) -> str:
    _safe_unit_value(value)
    if not Path(value).is_absolute():
        raise UserServiceError("unsafe service path")
    return value


def _quote(value: str) -> str:
    value = _safe_unit_value(value)
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError:
            raise UserServiceError("private service state is unavailable") from None
    try:
        info = path.lstat()
    except OSError:
        raise UserServiceError("private service state is unavailable") from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise UserServiceError("private service state is unsafe")


def _private_file(path: Path) -> bytes:
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise UserServiceError("private service file is unsafe")
        return path.read_bytes()
    except UserServiceError:
        raise
    except OSError:
        raise UserServiceError("private service file is unavailable") from None


def _create_private_file(path: Path, content: bytes) -> tuple[int, int]:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
        info = os.fstat(fd)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return info.st_dev, info.st_ino
    except FileExistsError:
        raise UserServiceError("service installation already has unverified state") from None
    except OSError:
        try:
            if "info" in locals():
                current = path.lstat()
                if (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino):
                    path.unlink()
        except OSError:
            pass
        raise UserServiceError("private service state could not be written") from None


def _run(command: list[str], *, timeout: int = 20) -> str:
    executable = shutil.which(command[0])
    if executable is None:
        raise UserServiceError("systemd user service support is unavailable")
    try:
        result = subprocess.run(
            [executable, *command[1:]],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise UserServiceError("systemd user service operation failed") from None
    if result.returncode != 0:
        raise UserServiceError("systemd user service operation failed")
    return result.stdout


def _manager(*arguments: str) -> str:
    return _run(["systemctl", "--user", *arguments])


def _unit_paths() -> tuple[Path, ...]:
    output = _run(["systemd-analyze", "--user", "unit-paths"])
    paths: list[Path] = []
    for line in output.splitlines():
        candidate = line.strip()
        if candidate.startswith("/"):
            path = Path(candidate)
            if path not in paths:
                paths.append(path)
    if not paths:
        raise UserServiceError("systemd user unit paths are unavailable")
    return tuple(paths)


def _user_unit_directory(paths: tuple[Path, ...]) -> Path:
    config_root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    preferred = (config_root / "systemd" / "user").absolute()
    if preferred in paths:
        return preferred
    standard = (Path.home() / ".config" / "systemd" / "user").absolute()
    if standard in paths:
        return standard
    raise UserServiceError("persistent user unit directory is unavailable")


def _entries(paths: tuple[Path, ...], unit_name: str) -> tuple[Path, ...]:
    found: list[Path] = []
    for root in paths:
        candidates = [root / unit_name]
        try:
            children = tuple(root.iterdir())
        except OSError:
            children = ()
        for child in children:
            if child.name.endswith((".wants", ".requires", ".upholds")) and child.is_dir():
                candidates.append(child / unit_name)
        for candidate in candidates:
            if os.path.lexists(candidate) and candidate not in found:
                found.append(candidate)
    return tuple(found)


def _link_points_to(path: Path, target: Path) -> bool:
    try:
        info = path.lstat()
        return stat.S_ISLNK(info.st_mode) and path.resolve(strict=True) == target.resolve(strict=True)
    except OSError:
        return False


def _assert_links(
    paths: tuple[Path, ...], unit_name: str, unit_file: Path
) -> tuple[Path, Path]:
    unit_dir = _user_unit_directory(paths)
    direct = unit_dir / unit_name
    wanted = unit_dir / "default.target.wants" / unit_name
    entries = _entries(paths, unit_name)
    if set(entries) != {direct, wanted}:
        raise UserServiceError("service registration does not match this installation")
    if not _link_points_to(direct, unit_file) or not _link_points_to(wanted, unit_file):
        raise UserServiceError("service registration does not match this installation")
    return direct, wanted


def _manager_state(unit_name: str) -> dict[str, str]:
    output = _manager(
        "show", unit_name,
        "--property=LoadState",
        "--property=FragmentPath",
        "--property=UnitFileState",
        "--property=ActiveState",
        "--property=DropInPaths",
    )
    values: dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def _require_bound_manager(unit_name: str, unit_file: Path) -> dict[str, str]:
    paths = _unit_paths()
    direct, _wanted = _assert_links(paths, unit_name, unit_file)
    state = _manager_state(unit_name)
    if (
        state.get("LoadState") != "loaded"
        or state.get("FragmentPath") != str(direct)
        or state.get("UnitFileState") != "enabled"
        or state.get("DropInPaths", "")
    ):
        raise UserServiceError("loaded service is not bound to this installation")
    return state


def _config_binding(role: str, xray_binary: str) -> dict[str, str]:
    if role not in {"server", "client"}:
        raise UserServiceError("invalid service role")
    workdir = Path.cwd().resolve(strict=True)
    state_dir = workdir / "state"
    _private_directory(state_dir)
    config_path = state_dir / f"xray-{role}.json"
    raw_config = _private_file(config_path)
    try:
        config = json.loads(raw_config.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise UserServiceError("Xray configuration is invalid") from None
    if not isinstance(config, dict):
        raise UserServiceError("Xray configuration is invalid")
    try:
        executable, metadata = verify_binary(xray_binary)
        validate_configs({role: config}, executable)
    except (OSError, RuntimeError, ValueError, TypeError):
        raise UserServiceError("pinned Xray configuration validation failed") from None
    python = os.path.abspath(sys.executable)
    if not Path(python).is_file() or not os.access(python, os.X_OK):
        raise UserServiceError("Python runtime is unavailable")
    source = str(_source_root())
    for value in (str(workdir), str(config_path), executable, python, source):
        _safe_absolute(value)
    return {
        "role": role,
        "workdir": str(workdir),
        "config_path": str(config_path),
        "config_sha256": hashlib.sha256(raw_config).hexdigest(),
        "xray_binary": executable,
        "xray_sha256": metadata.executable_sha256,
        "python": python,
        "source_root": source,
    }


def _render_unit(unit_name: str, binding: dict[str, str]) -> bytes:
    environment = (
        f"PYTHONPATH={binding['source_root']}",
        f"TRANSITVPN_PROXY_BIN={binding['xray_binary']}",
        f"TRANSITVPN_XRAY_BIN={binding['xray_binary']}",
    )
    command = [binding["python"], "-m", "transitvpn", "serve"]
    if binding["role"] == "client":
        command.append("--client")
    lines = [
        "[Unit]",
        "Description=TransitVPN managed user tunnel",
        "StartLimitIntervalSec=30s",
        "StartLimitBurst=5",
        "",
        "[Service]",
        "Type=simple",
        f"WorkingDirectory={_safe_absolute(binding['workdir'])}",
        "Environment=" + " ".join(_quote(value) for value in environment),
        "ExecStart=" + " ".join(_quote(value) for value in command),
        "Restart=on-failure",
        "RestartSec=1s",
        "StandardOutput=null",
        "StandardError=null",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _manifest(unit_name: str, binding: dict[str, str], unit_bytes: bytes) -> bytes:
    value = {
        "schema": _SCHEMA,
        "unit_name": unit_name,
        "binding": binding,
        "unit_sha256": hashlib.sha256(unit_bytes).hexdigest(),
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _installation(name: str) -> tuple[str, Path, Path, dict[str, object], bytes]:
    _slug, unit_name = _name(name)
    workdir = Path.cwd().resolve(strict=True)
    service_dir = workdir / _SERVICE_DIR
    _private_directory(service_dir)
    unit_file = service_dir / unit_name
    manifest_file = service_dir / f"{unit_name}.json"
    unit_bytes = _private_file(unit_file)
    manifest_bytes = _private_file(manifest_file)
    try:
        manifest = json.loads(manifest_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise UserServiceError("service ownership record is invalid") from None
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema", "unit_name", "binding", "unit_sha256"}
        or manifest.get("schema") != _SCHEMA
        or manifest.get("unit_name") != unit_name
        or not isinstance(manifest.get("binding"), dict)
        or manifest.get("unit_sha256") != hashlib.sha256(unit_bytes).hexdigest()
    ):
        raise UserServiceError("service ownership record is invalid")
    binding = manifest["binding"]
    if (
        set(binding) != {
            "role", "workdir", "config_path", "config_sha256", "xray_binary",
            "xray_sha256", "python", "source_root",
        }
        or binding.get("workdir") != str(workdir)
        or binding.get("source_root") != str(_source_root())
        or binding.get("python") != os.path.abspath(sys.executable)
        or binding.get("role") not in {"server", "client"}
        or binding.get("config_path") != str(workdir / "state" / f"xray-{binding.get('role')}.json")
        or not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("config_sha256", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(binding.get("xray_sha256", "")))
        or not Path(str(binding.get("xray_binary", ""))).is_absolute()
        or unit_bytes != _render_unit(unit_name, binding)
    ):
        raise UserServiceError("service ownership binding does not match this deployment")
    return unit_name, unit_file, manifest_file, manifest, unit_bytes


def _validate_current_config(binding: dict[str, str]) -> None:
    current = _config_binding(binding["role"], binding["xray_binary"])
    if current != binding:
        raise UserServiceError("service configuration differs from its installed binding")


def _verify_unit_file(unit_file: Path) -> None:
    _run(["systemd-analyze", "--user", "verify", str(unit_file)])


def _rollback_new_install(
    unit_name: str,
    unit_file: Path,
    unit_bytes: bytes,
    manifest_file: Path,
    manifest_bytes: bytes,
    created: dict[Path, tuple[int, int]],
    manager_touched: bool,
) -> None:
    if manager_touched:
        paths = _unit_paths()
        unit_dir = _user_unit_directory(paths)
        direct = unit_dir / unit_name
        state = _manager_state(unit_name)
        fragment = state.get("FragmentPath", "")
        if fragment and fragment != str(direct):
            raise UserServiceError("new service could not be safely rolled back")
        active_state = state.get("ActiveState", "")
        if active_state not in {"", "inactive", "failed", "not-found"}:
            if fragment != str(direct) or not _link_points_to(direct, unit_file):
                raise UserServiceError("new service could not be safely rolled back")
            _manager("stop", unit_name)
            stopped = _manager_state(unit_name)
            if (
                stopped.get("FragmentPath") != str(direct)
                or stopped.get("ActiveState") not in {"inactive", "failed"}
            ):
                raise UserServiceError("new service could not be safely rolled back")
        links = _entries(paths, unit_name)
        allowed = {
            direct,
            unit_dir / "default.target.wants" / unit_name,
        }
        if any(path not in allowed or not _link_points_to(path, unit_file) for path in links):
            raise UserServiceError("new service could not be safely rolled back")
        for path in links:
            path.unlink()
        _manager("daemon-reload")
        if _manager_state(unit_name).get("LoadState") != "not-found":
            raise UserServiceError("new service could not be safely rolled back")
    for path, expected_bytes in ((unit_file, unit_bytes), (manifest_file, manifest_bytes)):
        expected_inode = created.get(path)
        if expected_inode is None:
            continue
        info = path.lstat()
        if (info.st_dev, info.st_ino) != expected_inode or path.read_bytes() != expected_bytes:
            raise UserServiceError("new service files changed during rollback")
        path.unlink()
    try:
        unit_file.parent.rmdir()
    except OSError:
        pass


def install(name: str, *, role: str = "server", xray_binary: str = "xray") -> bool:
    """Install and start an enabled user service; return whether it was already installed."""
    _slug, unit_name = _name(name)
    binding = _config_binding(role, xray_binary)
    workdir = Path(binding["workdir"])
    service_dir = workdir / _SERVICE_DIR
    _private_directory(workdir / "state")
    if os.path.lexists(service_dir):
        _private_directory(service_dir)
    unit_file = service_dir / unit_name
    manifest_file = service_dir / f"{unit_name}.json"
    unit_bytes = _render_unit(unit_name, binding)
    manifest_bytes = _manifest(unit_name, binding, unit_bytes)
    if os.path.lexists(unit_file) or os.path.lexists(manifest_file):
        stored_name, stored_unit, _stored_manifest, stored, stored_bytes = _installation(name)
        if stored_name != unit_name or stored_bytes != unit_bytes or stored.get("binding") != binding:
            raise UserServiceError("existing service installation has a different binding")
        _verify_unit_file(stored_unit)
        _assert_links(_unit_paths(), unit_name, stored_unit)
        state = _require_bound_manager(unit_name, stored_unit)
        if state.get("ActiveState") != "active":
            raise UserServiceError("installed service is stopped; use service-start")
        _validate_current_config(binding)
        return True

    paths = _unit_paths()
    if _entries(paths, unit_name) or _manager_state(unit_name).get("LoadState") != "not-found":
        raise UserServiceError("service name is already in use")
    _private_directory(service_dir, create=True)
    created: dict[Path, tuple[int, int]] = {}
    created[unit_file] = _create_private_file(unit_file, unit_bytes)
    try:
        created[manifest_file] = _create_private_file(manifest_file, manifest_bytes)
    except UserServiceError:
        try:
            info = unit_file.lstat()
            if (info.st_dev, info.st_ino) == created[unit_file] and unit_file.read_bytes() == unit_bytes:
                unit_file.unlink()
        except OSError:
            pass
        raise

    manager_touched = False
    try:
        _verify_unit_file(unit_file)
        _validate_current_config(binding)
        manager_touched = True
        _manager("link", str(unit_file))
        _manager("daemon-reload")
        _manager("enable", unit_name)
        _manager("daemon-reload")
        _assert_links(_unit_paths(), unit_name, unit_file)
        _require_bound_manager(unit_name, unit_file)
        _validate_current_config(binding)
        _manager("start", unit_name)
        state = _require_bound_manager(unit_name, unit_file)
        if state.get("ActiveState") != "active":
            raise UserServiceError("installed service did not become active")
        return False
    except UserServiceError:
        try:
            _rollback_new_install(
                unit_name, unit_file, unit_bytes, manifest_file, manifest_bytes,
                created, manager_touched,
            )
        except (OSError, UserServiceError):
            pass
        raise


def _owned(name: str, *, validate_config: bool) -> tuple[str, Path, Path, dict[str, object], dict[str, str]]:
    unit_name, unit_file, manifest_file, manifest, _unit_bytes = _installation(name)
    binding = manifest["binding"]
    _verify_unit_file(unit_file)
    if validate_config:
        _validate_current_config(binding)
    _assert_links(_unit_paths(), unit_name, unit_file)
    state = _require_bound_manager(unit_name, unit_file)
    return unit_name, unit_file, manifest_file, manifest, state


def start(name: str) -> None:
    unit_name, unit_file, _manifest_file, _manifest_value, state = _owned(
        name, validate_config=True
    )
    if state.get("ActiveState") == "active":
        return
    _validate_current_config(_manifest_value["binding"])
    _manager("start", unit_name)
    if _require_bound_manager(unit_name, unit_file).get("ActiveState") != "active":
        raise UserServiceError("installed service did not become active")


def stop(name: str) -> None:
    unit_name, unit_file, _manifest_file, _manifest_value, state = _owned(
        name, validate_config=False
    )
    if state.get("ActiveState") in {"active", "activating", "deactivating"}:
        _manager("stop", unit_name)
    if _require_bound_manager(unit_name, unit_file).get("ActiveState") not in {"inactive", "failed"}:
        raise UserServiceError("installed service did not stop")


def uninstall(name: str) -> None:
    unit_name, unit_file, manifest_file, _manifest_value, state = _owned(
        name, validate_config=False
    )
    paths = _unit_paths()
    direct, wanted = _assert_links(paths, unit_name, unit_file)
    if state.get("ActiveState") in {"active", "activating", "deactivating"}:
        _manager("stop", unit_name)
    stopped = _require_bound_manager(unit_name, unit_file)
    if stopped.get("ActiveState") not in {"inactive", "failed"}:
        raise UserServiceError("installed service did not stop")
    if not _link_points_to(direct, unit_file) or not _link_points_to(wanted, unit_file):
        raise UserServiceError("service registration changed during removal")
    direct.unlink()
    wanted.unlink()
    _manager("daemon-reload")
    if _manager_state(unit_name).get("LoadState") != "not-found":
        raise UserServiceError("service remains loaded after removal")
    unit_file.unlink()
    manifest_file.unlink()
    try:
        unit_file.parent.rmdir()
    except OSError:
        pass
