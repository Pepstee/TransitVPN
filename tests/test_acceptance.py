"""Executable CLI boundaries. Real pinned-Xray validation is opt-in via its path.

The unattended acceptance demonstration is an import/parser smoke gate. These
checks exercise actual commands in isolated directories, never operator state.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

_REPO = Path(__file__).resolve().parent.parent
_BOOTSTRAP = ["bootstrap", "--host", "example.invalid", "--target",
              "example.invalid:443", "--server-name", "example.invalid", "--target-verified"]


def _run(*args: str, cwd: Path, script: bool = False) -> subprocess.CompletedProcess:
    entry = [str(_REPO / "transitvpn/cli.py")] if script else ["-m", "transitvpn"]
    env = {**os.environ, "PYTHONPATH": str(_REPO)}
    return subprocess.run([sys.executable, *entry, *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=60,
                          stdin=subprocess.DEVNULL)


@pytest.mark.parametrize("script", [False, True])
@pytest.mark.parametrize("flag, expected", [("--help", "Transit VPN management tool"),
                                            ("--version", "transitvpn 0.1.0")])
def test_cli_metadata(tmp_path, script, flag, expected):
    result = _run(flag, cwd=tmp_path, script=script)
    assert result.returncode == 0
    assert expected in result.stdout


@pytest.mark.parametrize("option", ["--host", "--target", "--server-name", "--target-verified"])
def test_bootstrap_requires_explicit_deployment(tmp_path, option):
    args = _BOOTSTRAP.copy()
    position = args.index(option)
    del args[position:position + (1 if option == "--target-verified" else 2)]
    result = _run(*args, "--dry-run", cwd=tmp_path)
    assert result.returncode == 2
    assert option in result.stderr
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("script", [False, True])
@pytest.mark.parametrize("dry_run", [False, True])
def test_bootstrap_missing_binary_fails_without_state(tmp_path, script, dry_run):
    result = _run(*_BOOTSTRAP, *(["--dry-run"] if dry_run else []),
                  "--xray-binary", str(tmp_path / "missing-xray"), cwd=tmp_path, script=script)
    assert result.returncode == 1
    assert "binary not found" in result.stderr
    assert not (tmp_path / "state").exists()
    assert "vless://" not in result.stdout and "private_key" not in result.stdout


def test_bootstrap_rejects_unpinned_binary_without_executing_it(tmp_path):
    binary = tmp_path / "xray"
    marker = tmp_path / "executed"
    binary.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
    binary.chmod(0o700)
    result = _run(*_BOOTSTRAP, "--dry-run", "--xray-binary", str(binary), cwd=tmp_path)
    assert result.returncode == 1
    assert "unverified Xray binary" in result.stderr
    assert not marker.exists()
    assert not (tmp_path / "state").exists()


@pytest.mark.parametrize("script", [False, True])
@pytest.mark.parametrize("command, code, message", [
    ("up", 1, "up: error:"), ("down", 0, "down: tunnel stopped"),
    ("status", 0, "status: not running"),
])
def test_lifecycle_without_state(tmp_path, script, command, code, message):
    result = _run(command, cwd=tmp_path, script=script)
    assert result.returncode == code
    assert message in result.stdout


def test_keygen_library_generates_distinct_valid_keys_without_stdout(tmp_path):
    # CLI credential printing was removed. Exercise retained generator through
    # a subprocess that validates keys internally and emits no secrets.
    script = '''
import base64
from uuid import UUID
from transitvpn.keygen import generate_keys
first, second = generate_keys(), generate_keys()
assert UUID(first.vless_uuid).version == 4
assert first.vless_uuid != second.vless_uuid
assert first.reality_private_key != second.reality_private_key
assert first.reality_private_key != first.reality_public_key
for value in (first.reality_private_key, first.reality_public_key):
    assert '+' not in value and '/' not in value
    assert len(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))) == 32
assert first.ss_password and first.ss_password != second.ss_password
'''
    result = subprocess.run([sys.executable, "-c", script], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(_REPO)},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""


def test_keygen_cli_cannot_print_credentials(tmp_path):
    result = _run("keygen", cwd=tmp_path)
    assert result.returncode == 2
    assert "invalid choice" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("dry_run", [True, False])
def test_real_pinned_binary_validates_matching_configs(tmp_path, dry_run):
    binary = os.environ.get("TRANSITVPN_XRAY_BIN")
    if not binary:
        pytest.skip("Set TRANSITVPN_XRAY_BIN for actual pinned-Xray validation")
    result = _run(*_BOOTSTRAP, *(["--dry-run"] if dry_run else []),
                  "--xray-binary", binary, cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    assert "validated server and client with Xray" in result.stdout
    assert "vless://" not in result.stdout and "ss://" not in result.stdout
    if dry_run:
        assert not (tmp_path / "state").exists()
        assert "wrote" not in result.stdout
    else:
        state = tmp_path / "state"
        assert state.stat().st_mode & 0o777 == 0o700
        assert {path.name for path in state.iterdir()} == {
            "xray-server.json", "xray-client.json", "xray-identity.json"}
        for path in state.iterdir():
            assert path.stat().st_mode & 0o777 == 0o600
            assert isinstance(json.loads(path.read_text()), dict)
        server = json.loads((state / "xray-server.json").read_text())
        user_id = server["inbounds"][0]["settings"]["clients"][0]["id"]
        private_key = server["inbounds"][0]["streamSettings"]["realitySettings"]["privateKey"]
        assert user_id not in result.stdout + result.stderr
        assert private_key not in result.stdout + result.stderr


def test_acceptance_delegates_and_reports_executed_smoke_boundaries(tmp_path):
    acceptance = _REPO / "acceptance"
    assert os.access(acceptance, os.X_OK)
    assert acceptance.read_text().splitlines()[0].startswith("#!/usr/bin/env bash")
    result = subprocess.run(["bash", str(acceptance)], cwd=tmp_path,
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    for boundary in ("py_compile", "imports", "credential boundary", "--help", "--version",
                     "subcommand up", "subcommand down", "subcommand status",
                     "bootstrap --dry-run", "keygen"):
        assert f"PASS: {boundary}" in result.stdout
    assert "All acceptance checks passed." in result.stdout


@pytest.mark.parametrize("module_path", [
    "transitvpn/__init__.py", "transitvpn/cli.py", "transitvpn/keygen.py",
    "transitvpn/cgnat.py", "transitvpn/config.py", "transitvpn/server.py",
    "transitvpn/qrcode.py",
])
def test_modules_compile_without_writing_source_cache(tmp_path, module_path):
    import py_compile
    py_compile.compile(str(_REPO / module_path),
                       cfile=str(tmp_path / "module.pyc"), doraise=True)


def test_retained_public_imports_in_subprocess(tmp_path):
    source = (
        "from transitvpn.cgnat import CgnatStatus, CgnatResult, detect_cgnat; "
        "from transitvpn.keygen import Keys, generate_keys; "
        "from transitvpn.config import VlessConfig, ShadowsocksConfig, RelayConfig, XrayDeployment; "
        "from transitvpn.server import build_xray_config, build_ss_config, build_server_config, build_client_config; "
        "from transitvpn.cli import build_parser, main"
    )
    result = subprocess.run([sys.executable, "-c", source], cwd=tmp_path,
                            env={**os.environ, "PYTHONPATH": str(_REPO)},
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
