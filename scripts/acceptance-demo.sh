#!/usr/bin/env bash
set -euo pipefail

# This demonstration and every descendant are detached from orchestration input.
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

exec python3 -m scripts.acceptance_demo </dev/null
