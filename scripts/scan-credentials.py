#!/usr/bin/env python3
"""Fail when repository or generated artefacts contain credential material.

False-positive fixtures must be annotated on their line (or the preceding line)
with ``credential-scan: allow RULE``.  Symbolic values containing PLACEHOLDER,
REDACTED, EXAMPLE, DUMMY, SENTINEL or CHANGEME, and the all-zero UUID, are
placeholders.
Diagnostics intentionally contain only the relative path and rule name.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GENERATED_PARTS = {
    "acceptance-evidence",
    "artifacts",
    "artefacts",
    "build",
    "client-configs",
    "dist",
    "evidence",
    "state",
}
PLACEHOLDER_WORDS = (
    "placeholder",
    "redacted",
    "example",
    "dummy",
    "sentinel",
    "changeme",
)
ALLOW = re.compile(r"credential-scan:\s*allow\s+([a-z-]+|all)\b", re.I)
UUID = re.compile(
    r"(?<![0-9a-f])([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})(?![0-9a-f])",
    re.I,
)
IMPORT_URI = re.compile(
    r"\b(?:vless://[0-9a-f-]{36}@[^\s'\"<>]+|ss://[^\s'\"<>]{12,}"
    r"|wg://[^\s'\"<>]+)",
    re.I,
)
NAMED_SECRET = re.compile(
    r"(?imx)\b(?:password|passwd|token|secret|credential|api[_-]?key|access[_-]?key|"
    r"private[_-]?key)\b\s*[:=]\s*(?:[rubf]{0,2})?(['\"])([^'\"\r\n]{8,})\1"
    r"|\b(?:password|passwd|token|secret|credential|api[_-]?key|access[_-]?key)\b"
    r"\s*[:=]\s*([A-Za-z0-9_+/%=-]{8,})(?=[ \t]*(?:\#|\r?$))"
    r"|\bAuthorization\s*:\s*(?:Bearer|Basic)\s+([A-Za-z0-9_+./=-]{8,})"
)
PEM = re.compile(
    (r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE " + r"KEY-----")
    + r"[\s\S]{16,}?"
    + (r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE " + r"KEY-----"),
)


def tracked_files() -> set[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if result.returncode:
        raise RuntimeError("git-ls-files")
    return {ROOT / os.fsdecode(name) for name in result.stdout.split(b"\0") if name}


def candidate_files() -> list[Path]:
    files = tracked_files()
    for directory_name in GENERATED_PARTS:
        directory = ROOT / directory_name
        if directory.is_dir():
            files.update(path for path in directory.rglob("*") if path.is_file())
    return sorted(files)


def placeholder(value: str) -> bool:
    lowered = value.lower()
    return (
        value == "00000000-0000-4000-8000-000000000000"
        or "{" in value
        or "}" in value
        or any(word in lowered for word in PLACEHOLDER_WORDS)
    )


def allowed(lines: list[str], position: int, rule: str) -> bool:
    line_number = "".join(lines).count("\n", 0, position)
    for index in (line_number, line_number - 1):
        if index < 0 or index >= len(lines):
            continue
        match = ALLOW.search(lines[index])
        if match and match.group(1).lower() in (rule, "all"):
            return True
    return False


def findings(path: Path) -> set[str]:
    try:
        content = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return set()
    lines = content.splitlines(keepends=True)
    found: set[str] = set()
    for rule, expression in (
        ("private-key", PEM),
        ("client-import-uri", IMPORT_URI),
        ("uuid-credential", UUID),
        ("password-token", NAMED_SECRET),
    ):
        for match in expression.finditer(content):
            value = next((group for group in match.groups()[::-1] if group), match.group(0))
            if not placeholder(value) and not allowed(lines, match.start(), rule):
                found.add(rule)
    return found


def main() -> int:
    try:
        files = candidate_files()
    except RuntimeError:
        print(".: repository-inventory", file=sys.stderr)
        return 2
    bad = False
    for path in files:
        for rule in sorted(findings(path)):
            print(f"{path.relative_to(ROOT)}: {rule}", file=sys.stderr)
            bad = True
    return int(bad)


if __name__ == "__main__":
    raise SystemExit(main())
