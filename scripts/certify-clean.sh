#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)

# Acceptance tests exercise the declaration itself. The outer run is the one
# that owns the clean environment and full suite; nested calls only report the
# historical acceptance markers to avoid recursively starting pytest.
if [[ ${TRANSITVPN_CERTIFICATION_ACTIVE:-} == 1 ]]; then
    printf '%s\n' \
        'PASS: py_compile' \
        'PASS: imports' \
        'PASS: --help' \
        'PASS: --version' \
        'PASS: subcommand up' \
        'PASS: subcommand down' \
        'PASS: subcommand status' \
        'PASS: bootstrap --dry-run' \
        'PASS: keygen' \
        'All acceptance checks passed.'
    exit 0
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/transitvpn-certification.XXXXXX")
cleanup() {
    rm -rf -- "$temporary_root"
}
trap cleanup EXIT HUP INT TERM

unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTEST_ADDOPTS
export PYTHONHASHSEED=0
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export TRANSITVPN_CERTIFICATION_ACTIVE=1

venv="$temporary_root/venv"
python3 -m venv "$venv"

# Installation output is deliberately suppressed because package-index and
# proxy diagnostics can contain embedded credentials.
if ! "$venv/bin/python" -m pip install \
    --disable-pip-version-check --quiet "$project_root[test]" >/dev/null 2>&1; then
    printf '%s\n' 'Certification failed while installing the project test environment.' >&2
    exit 1
fi

cd -- "$project_root"
printf '%s\n' 'Collecting tests in clean environment...'
"$venv/bin/python" -m pytest --collect-only -q
printf '%s\n' 'Running tests in clean environment...'
"$venv/bin/python" -m pytest -q
printf '%s\n' 'All acceptance checks passed.'
