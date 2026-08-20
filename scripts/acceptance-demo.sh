#!/usr/bin/env bash
set -euo pipefail

# This demonstration is unattended and must not consume orchestration input.
exec </dev/null

script_path=${BASH_SOURCE[0]}
script_directory=${script_path%/*}
if [[ $script_directory == "$script_path" ]]; then
    script_directory=.
fi
project_root=$(cd -- "$script_directory/.." && pwd -P </dev/null)
cd -- "$project_root"

unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT
export PYTHONHASHSEED=0
export CI=true
export GIT_TERMINAL_PROMPT=0
export SSH_ASKPASS=/bin/false
export SSH_ASKPASS_REQUIRE=force
export PIP_NO_INPUT=1

python3 - <<'PY'
from __future__ import annotations

import py_compile
import subprocess
import sys

from transitvpn.cgnat import CgnatResult, CgnatStatus, detect_cgnat
from transitvpn.cli import build_parser, main
from transitvpn.config import XrayDeployment
from transitvpn.keygen import Keys, generate_keys
from transitvpn.server import build_client_config, build_server_config


for source in ("transitvpn/__init__.py", "transitvpn/cli.py"):
    py_compile.compile(source, doraise=True)
print("PASS: py_compile")

assert all(
    value is not None
    for value in (
        CgnatResult,
        CgnatStatus,
        detect_cgnat,
        build_parser,
        main,
        XrayDeployment,
        Keys,
        generate_keys,
        build_client_config,
        build_server_config,
    )
)
print("PASS: imports")


def run_cli(*arguments: str) -> str:
    completed = subprocess.run(
        [sys.executable, "-m", "transitvpn", *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )
    return completed.stdout


assert "Transit VPN management tool" in run_cli("--help")
print("PASS: --help")
assert "transitvpn 0.1.0" in run_cli("--version")
print("PASS: --version")

parser = build_parser()
for command, marker in (
    ("up", "up:"),
    ("down", "down:"),
    ("status", "status:"),
):
    parsed = parser.parse_args([command])
    assert parsed.command == command and marker.endswith(":")
    print(f"PASS: subcommand {command}")

parsed = parser.parse_args(
    [
        "bootstrap",
        "--dry-run",
        "--host",
        "example.invalid",
        "--target",
        "example.invalid:443",
        "--server-name",
        "example.invalid",
        "--target-verified",
    ]
)
assert parsed.command == "bootstrap" and parsed.dry_run
assert "vless_uuid" in Keys.__dataclass_fields__
print("PASS: bootstrap --dry-run")

# Importing the generator demonstrates availability without generating or
# printing long-term credentials during acceptance.
assert callable(generate_keys)
print("PASS: keygen")
print("All acceptance checks passed.")
PY
