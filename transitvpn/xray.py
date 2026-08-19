"""Subprocess boundary for the pinned Xray executable."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Any

from transitvpn.config import XRAY_VERSION


def validate_configs(configs: list[dict[str, Any]], binary: str = "xray") -> dict[str, str]:
    """Verify binary identity and ask that exact binary to parse every config."""
    executable = shutil.which(binary)
    if executable is None:
        raise RuntimeError(f"Xray {XRAY_VERSION} is required; binary not found: {binary}")
    version = subprocess.run([executable, "version"], check=True, text=True,
                             capture_output=True, timeout=10).stdout.splitlines()[0]
    if re.search(rf"\b{re.escape(XRAY_VERSION)}\b", version) is None:
        raise RuntimeError(f"unsupported Xray binary (required {XRAY_VERSION}): {version}")
    digest = hashlib.sha256(Path(executable).read_bytes()).hexdigest()
    for config in configs:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as handle:
            json.dump(config, handle)
            handle.flush()
            subprocess.run([executable, "run", "-test", "-config", handle.name], check=True,
                           text=True, capture_output=True, timeout=20)
    return {"version": XRAY_VERSION, "sha256": digest}
