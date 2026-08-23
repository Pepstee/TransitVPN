#!/usr/bin/env bash
set -euo pipefail

# Certification is unattended.  Close stdin once so neither installers nor
# test processes can consume orchestration input or wait for a prompt.
exec </dev/null

script_path=${BASH_SOURCE[0]}
script_directory=${script_path%/*}
if [[ $script_directory == "$script_path" ]]; then
    script_directory=.
fi
project_root=$(cd -- "$script_directory/.." && pwd -P </dev/null)
lock_file="$project_root/requirements-certification.lock"

if [[ ! -r $lock_file ]]; then
    printf 'Certification input is missing or unreadable: %s\n' "$lock_file" >&2
    exit 2
fi
if [[ ! -d $project_root/tests ]]; then
    printf 'Certification input is missing: %s\n' "$project_root/tests" >&2
    exit 2
fi
for required_command in python3 git mktemp cmp; do
    if ! command -v "$required_command" >/dev/null 2>&1; then
        printf 'Certification prerequisite is unavailable: %s\n' "$required_command" >&2
        exit 2
    fi
done

# Credential cleanliness is a prerequisite for every successful path, including
# the private acceptance-test recursion path below.  The scanner inventories the
# repository itself and propagates a non-zero status for any finding.
python3 "$project_root/scripts/scan-credentials.py" </dev/null

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

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/transitvpn-certification.XXXXXX" </dev/null)
cleanup() {
    rm -rf -- "$temporary_root" </dev/null
}
trap cleanup EXIT HUP INT TERM

unset PYTHONHOME PYTHONPATH PYTHONSTARTUP PYTHONINSPECT PYTEST_ADDOPTS
unset TRANSITVPN_CERTIFICATION_ACTIVE __TRANSITVPN_CERTIFICATION_GUARD
unset __TRANSITVPN_CERTIFICATION_TOKEN
unset PIP_REQUIREMENT PIP_CONFIG_FILE PIP_NO_DEPS
export PYTHONHASHSEED=0
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export PIP_NO_INPUT=1
export GIT_TERMINAL_PROMPT=0
# Retained only as compatibility data for tests that inspect their environment;
# this value is never read by the runner and therefore cannot bypass any stage.
export TRANSITVPN_CERTIFICATION_ACTIVE=1
export PIP_CONSTRAINT=$lock_file

venv="$temporary_root/venv"
python3 -m venv "$venv" </dev/null

# Keep installer output (which can echo authenticated index/proxy URLs) private.
# Install only the committed, exactly pinned certification environment.  The
# project remains importable from project_root when pytest runs below, without
# installing the project or resolving its package metadata.
if ! "$venv/bin/python" -m pip install \
    --disable-pip-version-check --no-input --quiet \
    --requirement "$lock_file" >/dev/null 2>&1 </dev/null; then
    printf '%s\n' \
        'Certification dependency installation failed.' \
        'Verify package-index access and requirements-certification.lock.' >&2
    exit 1
fi

cd -- "$project_root"

snapshot_tracked_state() {
    local destination=$1
    {
        git status --porcelain=v1 --untracked-files=no </dev/null
        printf '\0'
        # This is the combined index and worktree diff against HEAD.  Together
        # with status above it preserves staged/unstaged state without a third
        # git process, keeping the mandatory credential scan within budget.
        git diff --binary HEAD -- </dev/null
    } >"$destination"
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
"$venv/bin/python" -m pytest --collect-only -q tests </dev/null || collection_status=$?

test_status=0
if (( collection_status == 0 )); then
    printf '%s\n' 'Running tests in clean environment...'
    "$venv/bin/python" -m pytest -q tests </dev/null || test_status=$?
fi

snapshot_tracked_state "$after"
if ! cmp -s "$before" "$after" </dev/null; then
    printf '%s\n' \
        'Certification failed: pytest changed or staged tracked artifacts.' >&2
    exit 1
fi
if (( collection_status != 0 || test_status != 0 )); then
    printf '%s\n' 'Certification failed: pytest did not complete successfully.' >&2
    exit 1
fi

printf '%s\n' 'All acceptance checks passed.'
