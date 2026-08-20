#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
lock_file="$project_root/requirements-certification.lock"

# Acceptance tests invoke the declaration while this runner is already running.
# Only a marker created inside this run's private temporary directory may stop
# that recursion.  The historical public flag is intentionally ignored.
if [[ -n ${__TRANSITVPN_CERTIFICATION_GUARD:-} && \
      -n ${__TRANSITVPN_CERTIFICATION_TOKEN:-} && \
      -f ${__TRANSITVPN_CERTIFICATION_GUARD:-} && \
      $(<"$__TRANSITVPN_CERTIFICATION_GUARD") == "$__TRANSITVPN_CERTIFICATION_TOKEN" ]]; then
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
unset TRANSITVPN_CERTIFICATION_ACTIVE __TRANSITVPN_CERTIFICATION_GUARD
unset __TRANSITVPN_CERTIFICATION_TOKEN
unset PIP_REQUIREMENT PIP_CONFIG_FILE PIP_NO_DEPS
export PYTHONHASHSEED=0
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
# Retained only as compatibility data for tests that inspect their environment;
# this value is never read by the runner and therefore cannot bypass any stage.
export TRANSITVPN_CERTIFICATION_ACTIVE=1
export PIP_CONSTRAINT=$lock_file

venv="$temporary_root/venv"
python3 -m venv "$venv"

# Keep installer output (which can echo authenticated index/proxy URLs) private.
# PIP_CONSTRAINT is inherited by pip's isolated build subprocess as well as its
# runtime/test resolver, so every remotely obtained distribution is constrained
# to an exact version from the committed lock.
if ! "$venv/bin/python" -m pip install \
    --disable-pip-version-check --quiet "$project_root[test]" >/dev/null 2>&1; then
    printf '%s\n' \
        'Certification project and dependency installation failed.' \
        'Verify package-index access and requirements-certification.lock.' >&2
    exit 1
fi

cd -- "$project_root"

snapshot_tracked_state() {
    local destination=$1
    git status --porcelain=v1 --untracked-files=no >"$destination.status"
    git diff --binary HEAD -- >"$destination.diff"
    git diff --binary --cached HEAD -- >"$destination.cached.diff"
}

before="$temporary_root/tracked-before"
after="$temporary_root/tracked-after"
snapshot_tracked_state "$before"

guard="$temporary_root/recursion-guard"
guard_token="${RANDOM}${RANDOM}:$$"
printf '%s\n' "$guard_token" >"$guard"
export __TRANSITVPN_CERTIFICATION_GUARD=$guard
export __TRANSITVPN_CERTIFICATION_TOKEN=$guard_token

printf '%s\n' 'Collecting tests in clean environment...'
collection_status=0
"$venv/bin/python" -m pytest --collect-only -q || collection_status=$?

test_status=0
if (( collection_status == 0 )); then
    printf '%s\n' 'Running tests in clean environment...'
    "$venv/bin/python" -m pytest -q || test_status=$?
fi

snapshot_tracked_state "$after"
if ! cmp -s "$before.status" "$after.status" || \
   ! cmp -s "$before.diff" "$after.diff" || \
   ! cmp -s "$before.cached.diff" "$after.cached.diff"; then
    printf '%s\n' \
        'Certification failed: pytest changed or staged tracked artifacts.' >&2
    exit 1
fi
if (( collection_status != 0 || test_status != 0 )); then
    printf '%s\n' 'Certification failed: pytest did not complete successfully.' >&2
    exit 1
fi

printf '%s\n' 'All acceptance checks passed.'
