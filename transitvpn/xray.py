"""Trust boundary for the pinned Xray executable."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
from typing import Any


# Upgrade this release and every digest below together.  The executable hashes
# are derived from the corresponding official release archives; checksum_source
# identifies the publisher's archive checksum metadata used for that release.
XRAY_VERSION = "26.7.11"
_RELEASE_ROOT = f"https://github.com/XTLS/Xray-core/releases/download/v{XRAY_VERSION}"


@dataclass(frozen=True)
class XrayBinaryMetadata:
    asset: str
    executable_sha256: str

    @property
    def checksum_source(self) -> str:
        return f"{_RELEASE_ROOT}/{self.asset}.dgst"


XRAY_BINARIES: dict[tuple[str, str], XrayBinaryMetadata] = {
    ("linux", "x86_64"): XrayBinaryMetadata(
        "Xray-linux-64.zip",
        "5200ed9b358cf380b2d9f1fe28c7e56220c0159adcd86a64592246d8257a043c",
    ),
    ("linux", "aarch64"): XrayBinaryMetadata(
        "Xray-linux-arm64-v8a.zip",
        "dd3ba298aa32af9442163ee791d54f562bd89aa860fed1d0c47306fb019c1e64",
    ),
    ("darwin", "x86_64"): XrayBinaryMetadata(
        "Xray-macos-64.zip",
        "7f15148309ed9939618b8d71e373f8fa5b374e6c8d3e0a43513da27be444a8d4",
    ),
    ("darwin", "arm64"): XrayBinaryMetadata(
        "Xray-macos-arm64-v8a.zip",
        "672590b1c35b1d8cd7ba3e786ab53189001f32e46369e18c0d81d099a4d66c52",
    ),
    ("windows", "x86_64"): XrayBinaryMetadata(
        "Xray-windows-64.zip",
        "4b43c5ef596f326b233717b585d31a85dd5cd5f77d8da872e75f7ebc00e99acb",
    ),
}


def _platform_key() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    machine = {"amd64": "x86_64", "arm64": "aarch64" if system == "linux" else "arm64"}.get(
        machine, machine
    )
    return system, machine


def verify_binary(binary: str = "xray") -> tuple[str, XrayBinaryMetadata]:
    """Return the absolute path only if it is the expected platform binary."""
    metadata = XRAY_BINARIES.get(_platform_key())
    if metadata is None:
        raise RuntimeError("no verified Xray binary is defined for this platform")

    executable = shutil.which(binary)
    if executable is None:
        raise RuntimeError(f"Xray {XRAY_VERSION} is required; binary not found")
    path = Path(executable).resolve()
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise RuntimeError("Xray binary could not be verified") from exc
    if not hashlib.compare_digest(digest, metadata.executable_sha256):
        raise RuntimeError(f"unverified Xray binary; pinned release {XRAY_VERSION} is required")

    # Do not execute an untrusted candidate to discover its version.  This is a
    # consistency check after the stronger byte-for-byte identity check.
    try:
        result = subprocess.run(
            [str(path), "version"], check=True, text=True, capture_output=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("verified Xray binary did not report its version") from exc
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    if re.search(rf"\b{re.escape(XRAY_VERSION)}\b", first_line) is None:
        raise RuntimeError(f"Xray version mismatch; pinned release {XRAY_VERSION} is required")
    return str(path), metadata


def validate_configs(configs: list[dict[str, Any]], binary: str = "xray") -> dict[str, str]:
    """Verify binary identity and ask that exact binary to parse every config."""
    executable, metadata = verify_binary(binary)
    for config in configs:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(config, handle)
            handle.flush()
            subprocess.run(
                [executable, "run", "-test", "-config", handle.name],
                check=True,
                text=True,
                capture_output=True,
                timeout=20,
            )
    return {
        "version": XRAY_VERSION,
        "sha256": metadata.executable_sha256,
        "checksum_source": metadata.checksum_source,
    }
