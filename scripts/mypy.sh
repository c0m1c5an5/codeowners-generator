#!/bin/bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/logging.sh"

git_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && git rev-parse --show-toplevel)"
log debug "Variable 'git_root' has value '${git_root}'"

cd "${git_root}"

source .venv/bin/activate
mypy --strict .
