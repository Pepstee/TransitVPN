"""Focused ownership checks for the persistent systemd user-service route."""

from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from transitvpn import cli, user_service


def _binding(workdir: Path, role: str = "server") -> dict[str, str]:
    return {
        "role": role,
        "workdir": str(workdir.resolve()),
        "config_path": str(workdir.resolve() / "state" / f"xray-{role}.json"),
        "config_sha256": hashlib.sha256(b"synthetic-private-config").hexdigest(),
        "xray_binary": "/usr/bin/xray",
        "xray_sha256": "a" * 64,
        "python": os.path.abspath(sys.executable),
        "source_root": str(user_service._source_root()),
    }


@pytest.fixture
def service_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workdir = tmp_path / "server deployment"
    workdir.mkdir(mode=0o700)
    (workdir / "state").mkdir(mode=0o700)
    unit_dir = tmp_path / "user systemd"
    unit_dir.mkdir(mode=0o700)
    monkeypatch.chdir(workdir)
    state: dict[str, object] = {
        "loaded": False,
        "unit_file": None,
        "active": "inactive",
        "file_state": "not-found",
        "starts": 0,
        "calls": [],
    }

    def manager(*arguments: str) -> str:
        calls = state["calls"]
        assert isinstance(calls, list)
        calls.append(arguments)
        if arguments[0] == "show":
            loaded = bool(state["loaded"])
            values = {
                "LoadState": "loaded" if loaded else "not-found",
                "FragmentPath": (
                    str(unit_dir / Path(state["unit_file"]).name) if loaded else ""
                ),
                "UnitFileState": str(state["file_state"]),
                "ActiveState": str(state["active"]),
                "DropInPaths": "",
            }
            return "".join(f"{key}={value}\n" for key, value in values.items())
        if arguments[0] == "link":
            unit_file = Path(arguments[1])
            (unit_dir / unit_file.name).symlink_to(unit_file)
            state["unit_file"] = unit_file
            state["loaded"] = True
            state["file_state"] = "linked"
        elif arguments[0] == "enable":
            unit_name = arguments[1]
            unit_file = state["unit_file"]
            assert isinstance(unit_file, Path)
            wants = unit_dir / "default.target.wants"
            wants.mkdir(exist_ok=True)
            (wants / unit_name).symlink_to(unit_file)
            state["file_state"] = "enabled"
        elif arguments[0] == "start":
            state["active"] = "active"
            state["starts"] = int(state["starts"]) + 1
        elif arguments[0] == "stop":
            state["active"] = "inactive"
        elif arguments[0] == "daemon-reload":
            unit_file = state["unit_file"]
            if not isinstance(unit_file, Path) or not os.path.lexists(unit_dir / unit_file.name):
                state.update(loaded=False, unit_file=None, file_state="not-found")
        else:
            raise AssertionError("unexpected systemd operation")
        return ""

    monkeypatch.setattr(user_service, "_unit_paths", lambda: (unit_dir,))
    monkeypatch.setattr(user_service, "_user_unit_directory", lambda _paths: unit_dir)
    monkeypatch.setattr(user_service, "_manager", manager)
    monkeypatch.setattr(user_service, "_verify_unit_file", lambda _path: None)
    monkeypatch.setattr(
        user_service,
        "_config_binding",
        lambda role, _xray: _binding(workdir, role),
    )
    return workdir, unit_dir, state


def test_install_is_idempotent_and_owned_lifecycle_removes_only_its_links(
    service_sandbox,
    tmp_path: Path,
) -> None:
    workdir, unit_dir, state = service_sandbox
    slug = "acceptance"
    unit_name = f"transitvpn-{slug}.service"
    unit_path = workdir / "state" / "services" / unit_name
    manifest_path = workdir / "state" / "services" / f"{unit_name}.json"
    unrelated = tmp_path / "unrelated.service"
    unrelated.write_text("kept", encoding="utf-8")
    (unit_dir / "default.target.wants").mkdir()
    (unit_dir / "default.target.wants" / "unrelated.service").symlink_to(unrelated)

    assert not user_service.install(slug)
    initial_unit = unit_path.read_bytes()
    initial_manifest = manifest_path.read_bytes()
    initial_inode = unit_path.stat().st_ino
    assert state["starts"] == 1
    assert user_service.install(slug)
    assert unit_path.stat().st_ino == initial_inode
    assert unit_path.read_bytes() == initial_unit
    assert manifest_path.read_bytes() == initial_manifest
    assert state["starts"] == 1

    user_service.stop(slug)
    assert state["active"] == "inactive"
    user_service.start(slug)
    assert state["active"] == "active"
    assert state["starts"] == 2
    user_service.uninstall(slug)
    assert not unit_path.exists()
    assert not manifest_path.exists()
    assert not (unit_dir / unit_name).exists()
    assert not (unit_dir / "default.target.wants" / unit_name).exists()
    assert (unit_dir / "default.target.wants" / "unrelated.service").is_symlink()


def test_invalid_config_is_rejected_before_manager_or_service_state_mutation(
    service_sandbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workdir, _unit_dir, state = service_sandbox

    def fail_validation(*_args, **_kwargs):
        raise user_service.UserServiceError("private validation diagnostic")

    monkeypatch.setattr(user_service, "_config_binding", fail_validation)
    with pytest.raises(user_service.UserServiceError):
        user_service.install("invalid")
    assert state["calls"] == []
    assert not (workdir / "state" / "services").exists()


def test_same_name_foreign_registration_is_preserved(service_sandbox, tmp_path: Path) -> None:
    workdir, unit_dir, state = service_sandbox
    foreign = tmp_path / "foreign.service"
    foreign.write_text("foreign", encoding="utf-8")
    unit_name = "transitvpn-collision.service"
    (unit_dir / unit_name).symlink_to(foreign)
    with pytest.raises(user_service.UserServiceError):
        user_service.install("collision")
    assert user_service._link_points_to(unit_dir / unit_name, foreign)
    assert not (workdir / "state" / "services").exists()
    assert state["calls"] == []


def test_symlinked_owned_unit_file_is_refused_without_touching_target(
    service_sandbox,
    tmp_path: Path,
) -> None:
    workdir, _unit_dir, state = service_sandbox
    service_dir = workdir / "state" / "services"
    service_dir.mkdir(mode=0o700)
    target = tmp_path / "foreign-unit"
    target.write_text("foreign data", encoding="utf-8")
    unit_path = service_dir / "transitvpn-unsafe.service"
    unit_path.symlink_to(target)
    with pytest.raises(user_service.UserServiceError):
        user_service.install("unsafe")
    assert target.read_text(encoding="utf-8") == "foreign data"
    assert unit_path.is_symlink()
    assert state["calls"] == []


def test_repeat_install_failure_preserves_existing_artifacts_and_running_unit(
    service_sandbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workdir, _unit_dir, state = service_sandbox
    unit_path = Path.cwd() / "state" / "services" / "transitvpn-preserve.service"
    manifest_path = Path(str(unit_path) + ".json")
    assert user_service.install("preserve") is False
    unit_before = (unit_path.stat().st_ino, unit_path.read_bytes())
    manifest_before = (manifest_path.stat().st_ino, manifest_path.read_bytes())

    def refuse(*_args, **_kwargs):
        raise user_service.UserServiceError("sensitive configuration detail")

    monkeypatch.setattr(user_service, "_validate_current_config", refuse)
    with pytest.raises(user_service.UserServiceError):
        user_service.install("preserve")
    assert (unit_path.stat().st_ino, unit_path.read_bytes()) == unit_before
    assert (manifest_path.stat().st_ino, manifest_path.read_bytes()) == manifest_before
    assert state["active"] == "active"


def test_rollback_refuses_to_stop_active_unit_without_exact_fragment_binding(
    service_sandbox,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workdir, _unit_dir, _fake_state = service_sandbox
    service_dir = workdir / "state" / "services"
    unit_name = "transitvpn-race.service"
    unit_file = service_dir / unit_name
    manifest_file = Path(str(unit_file) + ".json")
    manager_calls: list[tuple[str, ...]] = []
    states = iter((
        {"LoadState": "not-found", "FragmentPath": "", "ActiveState": "inactive"},
        {"LoadState": "loaded", "FragmentPath": "", "ActiveState": "active"},
    ))
    monkeypatch.setattr(user_service, "_manager_state", lambda _unit: next(states))

    def fail_link(*arguments: str) -> str:
        manager_calls.append(arguments)
        if arguments[0] == "link":
            raise user_service.UserServiceError("synthetic manager failure")
        raise AssertionError("rollback must not signal an unbound active unit")

    monkeypatch.setattr(user_service, "_manager", fail_link)
    with pytest.raises(user_service.UserServiceError):
        user_service.install("race")
    assert manager_calls and manager_calls[0][0] == "link"
    assert all(call[0] != "stop" for call in manager_calls)
    assert unit_file.is_file()
    assert manifest_file.is_file()
    assert stat.S_IMODE(unit_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(manifest_file.stat().st_mode) == 0o600


def test_cli_errors_are_fixed_and_do_not_print_private_exception_text(
    service_sandbox,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def refuse(*_args, **_kwargs):
        raise user_service.UserServiceError("credential=do-not-print-this")

    monkeypatch.setattr(user_service, "install", refuse)
    assert cli.main(["service-install", "--name", "safe"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "service-install: error: user service operation was refused\n"
    assert "do-not-print-this" not in captured.err


def test_unit_renderer_rejects_systemd_specifier_and_variable_expansion(
    service_sandbox,
) -> None:
    _workdir, _unit_dir, _state = service_sandbox
    binding = _binding(Path.cwd())
    binding["workdir"] = "/tmp/unsafe%h"
    with pytest.raises(user_service.UserServiceError):
        user_service._render_unit("transitvpn-unsafe.service", binding)

    binding["workdir"] = "/tmp/unsafe$(touch)"
    with pytest.raises(user_service.UserServiceError):
        user_service._render_unit("transitvpn-unsafe.service", binding)
